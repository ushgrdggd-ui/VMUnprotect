using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
using System.Diagnostics;
using System.Collections.Generic;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.IO;
using AsmResolver.PE.File;
using AsmResolver.PE.Imports;
using AsmResolver.PE.Exports;
using AsmResolver.PE;
using AsmResolver.DotNet.Serialized;
using AsmResolver.DotNet.Builder;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Metadata.Tables;
using AsmResolver.PE.DotNet.Metadata.Tables.Rows;
using AsmResolver;
class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool DeleteFile(string lpFileName);

    [DllImport("kernel32.dll")]
    static extern uint SetErrorMode(uint uMode);

    [DllImport("kernel32.dll")]
    static extern bool SetThreadErrorMode(uint dwNewMode, out uint lpOldMode);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    const uint SEM_FAILCRITICALERRORS = 0x0001;
    const uint SEM_NOGPFAULTERRORBOX = 0x0002;
    const uint SEM_NOOPENFILEERRORBOX = 0x8000;

    static void SanitizePEFile(PEFile peFile)
    {
        try
        {
            
            
            var dataDirectory = peFile.OptionalHeader.DataDirectories[14];
            if (dataDirectory.IsPresentInPE)
            {
                
                
            }
        }
        catch { }
    }

    static async Task Main(string[] args)
    {
        const string asciiArt = @"
_________                __                 
\_   ___ \  ____________/  |_  ____ ___  ___
/    \  \/ /  _ \_  __ \   __\/ __ \\  \/  /
\     \___(  <_> )  | \/|  | \  ___/ >    < 
 \______  /\____/|__|   |__|  \___  >__/\_ \
        \/                        \/      \/
                VMUnprotect.dumper
         by dwey
";
        Console.Title = "VMUnprotect.Dumper";
        Console.WriteLine(asciiArt);

        uint flags = SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX;
        SetErrorMode(flags);
        try { SetThreadErrorMode(flags, out _); } catch { }

        AppDomain.CurrentDomain.UnhandledException += (s, e) => { };
        TaskScheduler.UnobservedTaskException += (s, e) => { e.SetObserved(); };

        var dumperDir = Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName);

        if (args.Length == 0)
        {
            Console.WriteLine("Usage: VMUnprotect.Dumper.exe <protected .NET file>");
            return;
        }

        var target = Path.GetFullPath(args[0]);
        if (!File.Exists(target))
        {
            Console.WriteLine($"File not found: {target}");
            return;
        }

        var targetDir = Path.GetDirectoryName(target);
        if (!string.IsNullOrEmpty(targetDir)) Directory.SetCurrentDirectory(targetDir);

        AppDomain.CurrentDomain.AssemblyResolve += (sender, resolveArgs) =>
        {
            try
            {
                var assemblyName = new AssemblyName(resolveArgs.Name).Name;
                var searchPaths = new List<string> { targetDir };
                if (!string.IsNullOrEmpty(dumperDir) && dumperDir != targetDir) searchPaths.Add(dumperDir);

                var extensions = new[] { ".dll", ".exe" };
                foreach (var path in searchPaths)
                {
                    foreach (var ext in extensions)
                    {
                        var assemblyPath = Path.Combine(path, assemblyName + ext);
                        if (File.Exists(assemblyPath))
                        {
                            try { return Assembly.LoadFrom(assemblyPath); } catch { }
                        }
                    }
                }
            }
            catch { }
            return null;
        };

        var output = $"{Path.GetFileNameWithoutExtension(target)}-decrypted.exe";
        try { DeleteFile(target + ":Zone.Identifier"); } catch { }

        Assembly assembly;
        try
        {
            assembly = Assembly.LoadFrom(target);
        }
        catch
        {
            try { assembly = Assembly.Load(File.ReadAllBytes(target)); } catch { return; }
        }

        var manifestModule = assembly.ManifestModule;
        var stubsForTrace = new List<(string Name, long Address)>();
        var module = ModuleDefinition.FromFile(target);

        Console.WriteLine("Preparing initialization methods...");
        try
        {
            foreach (var typeDef in module.GetAllTypes())
            {
                var cctorDef = typeDef.GetStaticConstructor();
                if (cctorDef != null)
                {
                    try
                    {
                        var resolved = assembly.ManifestModule.ResolveMethod(cctorDef.MetadataToken.ToInt32());
                        if (resolved != null) RuntimeHelpers.PrepareMethod(resolved.MethodHandle);
                    }
                    catch { }
                }
            }
        }
        catch { }

        var hInstance = Marshal.GetHINSTANCE(manifestModule);
        Console.WriteLine("Aggressively preparing all methods...");
        
        int preparedCount = 0;
        List<Type> allTypes = new List<Type>();
        try
        {
            allTypes = assembly.GetTypes().SelectMany(t => GetAllNestedTypes(t)).Distinct().ToList();
        }
        catch (ReflectionTypeLoadException ex)
        {
            allTypes = ex.Types.Where(t => t != null).SelectMany(t => GetAllNestedTypes(t)).Distinct().ToList();
        }

        foreach (var type in allTypes)
        {
            if (preparedCount % 100 == 0) Console.Write(".");
            try { RuntimeHelpers.RunClassConstructor(type.TypeHandle); } catch { }

            var methods = type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly);
            var ctors = type.GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance);
            
            foreach (var method in methods.Cast<MethodBase>().Concat(ctors))
            {
                try
                {
                    if (method.MethodHandle.Value != IntPtr.Zero)
                    {
                        RuntimeHelpers.PrepareMethod(method.MethodHandle);
                        preparedCount++;
                        
                        if (method.Name.Length == 8)
                        {
                            var addr = method.MethodHandle.GetFunctionPointer();
                            stubsForTrace.Add(($"{type.Name}.{method.Name}", addr.ToInt64()));
                        }
                    }
                }
                catch { }
            }
        }
        Console.WriteLine($"\nPrepared {preparedCount} methods.");

        var diskImage = PEFile.FromFile(target);
        uint originalEP = diskImage.OptionalHeader.AddressOfEntrypoint;

        Console.WriteLine("Searching for real OEP...");
        IntPtr possibleOEP = IntPtr.Zero;
        var sw = Stopwatch.StartNew();
        while (sw.Elapsed.TotalSeconds < 15)
        {
            byte[] buf = new byte[6];
            if (ReadProcessMemory(GetCurrentProcess(), (IntPtr)(hInstance.ToInt64() + originalEP), buf, buf.Length, out _))
            {
                if (buf[0] != 0xCC && buf[0] != 0x00)
                {
                    possibleOEP = (IntPtr)(hInstance.ToInt64() + originalEP);
                    break;
                }
            }
            await Task.Delay(50);
        }

        if (possibleOEP == IntPtr.Zero) possibleOEP = (IntPtr)(hInstance.ToInt64() + originalEP);
        Console.WriteLine($"[+] OEP: 0x{possibleOEP.ToInt64():X}");

        var runtimeImage = PEFile.FromModuleBaseAddress(hInstance, PEMappingMode.Mapped);
        runtimeImage.OptionalHeader.Magic = diskImage.OptionalHeader.Magic;
        runtimeImage.OptionalHeader.AddressOfEntrypoint = originalEP;

        
        SanitizePEFile(runtimeImage);

        
        Console.WriteLine("Aggressively stripping non-essential sections...");
        for (int i = runtimeImage.Sections.Count - 1; i >= 0; i--)
        {
            var section = runtimeImage.Sections[i];
            string name = (section.Name?.ToString() ?? "").ToLower();
            if (name.Contains(".vmp") || name.Contains(".ext") || name.Contains(".reloc") || name.Contains(".rsrc") || name.Contains(".tls"))
            {
                
                if (name == ".rsrc" || name == ".text") continue; 
                
                Console.WriteLine($"[-] Stripping section: {name}");
                runtimeImage.Sections.RemoveAt(i);
            }
        }
        
        
        
        
        Console.WriteLine("Cleaning runtime resources...");
        try {
            
            
            
            
            
            
            
        } catch {}

        
        runtimeImage.Write(output);
        Console.WriteLine($"Saved cleaned dump: {output} ({new FileInfo(output).Length / 1024} KB)");

        
        var dumpedModule = ModuleDefinition.FromFile(runtimeImage);

        
        Console.WriteLine("Cleaning module resources...");
        for (int i = dumpedModule.Resources.Count - 1; i >= 0; i--)
        {
             var entry = dumpedModule.Resources[i];
             if ((object)entry.Name != null) {
                 string rName = entry.Name.ToString() ?? "";
                 
                 if (!string.IsNullOrEmpty(rName) && !rName.EndsWith(".resources") && !rName.Contains("Version") && !rName.Contains("Manifest")) {
                     Console.WriteLine($"[-] Removing module resource: {rName}");
                     dumpedModule.Resources.RemoveAt(i);
                 }
             }
        }
        
        try
        {
            RenameSymbolsAndSave(dumpedModule, output, assembly);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Renaming failed: {ex.Message}");
            if (ex.InnerException != null) Console.WriteLine($"Inner: {ex.InnerException.Message}");
        }

        Console.WriteLine("\nDone. Press any key to exit.");
        Console.ReadKey();
    }

    static void RenameSymbolsAndSave(ModuleDefinition module, string dumpedPath, Assembly assembly)
    {
        Console.WriteLine("Starting deep metadata sanitization and renaming...");

        
        ZeroOutVMData(module);

        var importer = new ReferenceImporter(module);
        
        
        if (module.Assembly != null) {
            module.Assembly.Name = Path.GetFileNameWithoutExtension(dumpedPath);
            module.Assembly.CustomAttributes.Clear();
            module.Assembly.SecurityDeclarations.Clear();
        }
        module.Name = Path.GetFileName(dumpedPath);
        module.CustomAttributes.Clear();

        
        module.CustomAttributes.Clear();
        module.Assembly?.CustomAttributes.Clear();

        
        

        
        foreach (var type in module.GetAllTypes())
        {
            try { 
                if (string.IsNullOrEmpty(type.Name)) type.Name = $"Type_{type.MetadataToken.ToInt32():X}";
                type.CustomAttributes.Clear();
                type.SecurityDeclarations.Clear();

                foreach (var method in type.Methods)
                {
                    if (string.IsNullOrEmpty(method.Name)) method.Name = $"Method_{method.MetadataToken.ToInt32():X}";
                    method.CustomAttributes.Clear();
                    method.SecurityDeclarations.Clear();
                    foreach (var param in method.ParameterDefinitions) {
                        param.CustomAttributes.Clear();
                        if (string.IsNullOrEmpty(param.Name)) param.Name = $"param_{param.MetadataToken.ToInt32():X}";
                    }
                }

                foreach (var field in type.Fields)
                {
                    if (string.IsNullOrEmpty(field.Name)) field.Name = $"Field_{field.MetadataToken.ToInt32():X}";
                    field.CustomAttributes.Clear();
                }
                
                foreach (var prop in type.Properties)
                {
                    if (string.IsNullOrEmpty(prop.Name)) prop.Name = $"Prop_{prop.MetadataToken.ToInt32():X}";
                    prop.CustomAttributes.Clear();
                }
                
                foreach (var ev in type.Events)
                {
                    if (string.IsNullOrEmpty(ev.Name)) ev.Name = $"Event_{ev.MetadataToken.ToInt32():X}";
                    ev.CustomAttributes.Clear();
                }
            } catch { }
        }

        
        try {
            if (module.DotNetDirectory != null) {
                module.DotNetDirectory.VTableFixups.Clear();
                module.DotNetDirectory.Flags &= ~DotNetDirectoryFlags.StrongNameSigned;
                module.DotNetDirectory.Flags |= DotNetDirectoryFlags.ILOnly;
                module.DotNetDirectory.CodeManagerTable = null;
                module.DotNetDirectory.ManagedNativeHeader = null;
            }
            module.Resources.Clear();
            module.NativeResourceDirectory = null;
            module.DebugData.Clear();
        } catch { }

        var stringMap = new Dictionary<string, List<string>>();
        var methodToProp = new Dictionary<uint, string>();
        var methodToEv = new Dictionary<uint, string>();
        var methodFreq = new Dictionary<IMethodDescriptor, int>();
        var vmDispatchers = new HashSet<IMethodDescriptor>();

        
        foreach (var type in module.GetAllTypes())
        {
            foreach (var prop in type.Properties)
            {
                if ((string?)prop.Name != null && !IsObfuscatedName(prop.Name))
                {
                    if (prop.GetMethod != null) methodToProp[(uint)prop.GetMethod.MetadataToken.ToInt32()] = "get_" + prop.Name;
                    if (prop.SetMethod != null) methodToProp[(uint)prop.SetMethod.MetadataToken.ToInt32()] = "set_" + prop.Name;
                }
            }
            foreach (var ev in type.Events)
            {
                if ((string?)ev.Name != null && !IsObfuscatedName(ev.Name))
                {
                    if (ev.AddMethod != null) methodToEv[(uint)ev.AddMethod.MetadataToken.ToInt32()] = "add_" + ev.Name;
                    if (ev.RemoveMethod != null) methodToEv[(uint)ev.RemoveMethod.MetadataToken.ToInt32()] = "remove_" + ev.Name;
                }
            }
            foreach (var method in type.Methods)
            {
                if (method.CilMethodBody == null) continue;
                foreach (var instr in method.CilMethodBody.Instructions)
                {
                    if (instr.OpCode.Code == CilCode.Ldstr && instr.Operand is string s && s != null && s.Length > 3)
                    {
                        if (!stringMap.ContainsKey(s)) stringMap[s] = new List<string>();
                        stringMap[s].Add(method.FullName ?? "UnknownMethod");
                    }
                    if (instr.Operand is IMethodDescriptor target && target != null)
                    {
                        if (!methodFreq.ContainsKey(target)) methodFreq[target] = 0;
                        methodFreq[target]++;
                    }
                }
            }
        }

        foreach (var entry in methodFreq) if (entry.Key != null && (string?)entry.Key.Name != null && entry.Value > 10 && IsObfuscatedName(entry.Key.Name)) vmDispatchers.Add(entry.Key);

        List<string> xorKeys = new List<string>();
        try { xorKeys = DiscoverXorKeys(module); } catch {}
        int decryptedCount = 0;
        var globalStringMap = new Dictionary<int, string>();

        
        FieldInfo? proxyFieldInfo = null;
        object[]? proxyTableValues = null;

        foreach (var type in module.GetAllTypes())
        {
            
            
            
            
            
            if (type.IsValueType && type.Fields.Count >= 5 && IsObfuscatedName(type.Name))
            {
                if (type.Fields.Any(f => f.Signature != null && f.Signature.FieldType.FullName.Contains("UInt32")))
                {
                    
                }
            }

            foreach (var method in type.Methods)
            {
                if (method.CilMethodBody == null) continue;
                
                
                
                
                
                foreach (var instr in method.CilMethodBody.Instructions)
                {
                    if (instr.OpCode.Code == CilCode.Ldstr && instr.Operand is string s)
                    {
                        string dec = DecryptSnatString(s, xorKeys);
                        if (!IsObfuscatedName(dec) && dec.Length > 3) { 
                            instr.Operand = dec; 
                            decryptedCount++; 
                            if (!stringMap.ContainsKey(dec)) stringMap[dec] = new List<string>();
                            stringMap[dec].Add(type.FullName);
                        }
                    }
                }
            }
        }

        
        
        
        var proxyTables = new Dictionary<IFieldDescriptor, object[]>();
        var potentialHandlerArrays = new Dictionary<IFieldDescriptor, int>();
        var globalDevirtMap = new Dictionary<IFieldDescriptor, Dictionary<int, IMethodDescriptor>>();
        
        foreach (var type in module.GetAllTypes()) {
            foreach (var method in type.Methods) {
                if (method.CilMethodBody == null) continue;
                var instrs = method.CilMethodBody.Instructions;
                for (int i = 0; i < instrs.Count - 2; i++) {
                     if ((instrs[i].OpCode.Code == CilCode.Ldsfld || instrs[i].OpCode.Code == CilCode.Ldfld) && instrs[i].Operand is IFieldDescriptor f && f != null) {
                         
                         for (int j = i + 1; j < Math.Min(i + 15, instrs.Count); j++) {
                             if (instrs[j].OpCode.Code == CilCode.Ldelem_Ref) {
                                 if (!potentialHandlerArrays.ContainsKey(f)) potentialHandlerArrays[f] = 0;
                                 potentialHandlerArrays[f]++;
                                 break;
                             }
                             if (instrs[j].OpCode.Code == CilCode.Ret) break;
                         }
                     }
                }
            }
        }
        
        
        foreach (var handlerArrayField in potentialHandlerArrays.Where(x => x.Value > 0).Select(x => x.Key)) {
            
            var staticMap = ExtractProxyTableStatic(handlerArrayField);
            if (staticMap.Count > 0) {
                globalDevirtMap[handlerArrayField] = staticMap;
                Console.WriteLine($"[+] Extracted Proxy Table (Static): {handlerArrayField.FullName} ({staticMap.Count} entries)");
                continue;
            }

            
            try {
                 if (handlerArrayField.DeclaringType is IMetadataMember metadataMember) {
                     var token = metadataMember.MetadataToken;
                     var fieldType = assembly.ManifestModule.ResolveType(token.ToInt32());
                     if (fieldType != null) {
                         RuntimeHelpers.RunClassConstructor(fieldType.TypeHandle);
                         var field = fieldType.GetField(handlerArrayField.Name!, BindingFlags.Static | BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
                         if (field != null) {
                             object? rawVal = null;
                             if (field.IsStatic) rawVal = field.GetValue(null);
                             else {
                                 
                                 
                                 var instanceField = fieldType.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
                                     .FirstOrDefault(f => f.FieldType == fieldType);
                                 
                                 
                                 if (instanceField == null) {
                                     foreach (var t in assembly.GetTypes()) {
                                         instanceField = t.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
                                             .FirstOrDefault(f => f.FieldType == fieldType);
                                         if (instanceField != null) break;
                                     }
                                 }

                                 if (instanceField != null) {
                                     var instance = instanceField.GetValue(null);
                                     if (instance != null) rawVal = field.GetValue(instance);
                                 }
                             }

                             if (rawVal is Array arr) {
                                 var realProxyArray = new object[arr.Length];
                                 for(int k=0; k<arr.Length; k++) realProxyArray[k] = arr.GetValue(k);
                                 proxyTables[handlerArrayField] = realProxyArray;
                                 Console.WriteLine($"[+] Extracted Proxy Table: {handlerArrayField.FullName} ({arr.Length} entries)");
                             }
                         }
                     }
                 }
            } catch { }
        }

        
        int typeCount = 0, methodCount = 0, devirtCount = 0;
        var typeNameCounters = new Dictionary<string, int>();

        
        foreach (var table in proxyTables) {
            if (globalDevirtMap.ContainsKey(table.Key)) continue; 
            var map = new Dictionary<int, IMethodDescriptor>();
            for (int i = 0; i < table.Value.Length; i++) {
                if (table.Value[i] is Delegate del) {
                    try { map[i] = importer.ImportMethod(del.Method); } catch { }
                }
            }
            if (map.Count > 0) globalDevirtMap[table.Key] = map;
        }

        foreach (var type in module.GetAllTypes())
        {
            if (type.Fields.Count > 0 && type.Fields[0] is IFieldDescriptor firstField && firstField != null && proxyTables.ContainsKey(firstField)) continue;
            
            
            string? recoveredName = TryRecoverName(type, stringMap) ?? InferTypeNameFromContent(type, new List<string>());
            if (recoveredName != null && IsObfuscatedName(type.Name))
            {
                if (!typeNameCounters.ContainsKey(recoveredName)) typeNameCounters[recoveredName] = 0;
                int c = typeNameCounters[recoveredName]++;
                type.Name = c == 0 ? recoveredName : $"{recoveredName}_{c}";
                typeCount++;
            }
            else if (IsObfuscatedName(type.Name))
            {
                type.Name = $"Type_{type.MetadataToken.ToInt32():X}";
                typeCount++;
            }

            

            foreach (var method in type.Methods)
            {
                var body = method.CilMethodBody;
                if (body == null) continue;

                var instrs = body.Instructions;
                
                
                bool isCritical = false;
                
                
                
                if (method.Name == ".cctor" && method.DeclaringType?.Name == "<Module>") 
                    goto SkipModification;

                
                string? potentialMethodName = null;
                if (IsObfuscatedName(method.Name)) potentialMethodName = TryRecoverMethodNameWithXor(method, stringMap, new List<string>());
                string currentMethodName = potentialMethodName ?? method.Name?.ToString() ?? "";
                
                
                if (methodToEv.ContainsKey((uint)method.MetadataToken.ToInt32())) isCritical = true;
                if (methodToProp.ContainsKey((uint)method.MetadataToken.ToInt32())) isCritical = true;
                
                
                if (method.IsConstructor || currentMethodName.StartsWith("add_") || currentMethodName.StartsWith("remove_") || 
                    currentMethodName.StartsWith("get_") || currentMethodName.StartsWith("set_") ||
                    currentMethodName.Contains("TypeFromHandle") || method.DeclaringType?.Name == "GetTypeFromHandle") 
                    isCritical = true;

                
                if (method.Signature != null && (method.Signature.ParameterTypes.Any(p => p.ElementType == ElementType.ByRef) || method.Signature.ReturnType.ElementType == ElementType.ByRef))
                    isCritical = true;

                
                var jumpTargets = new HashSet<CilInstruction>();
                foreach (var instr in instrs) {
                    if (instr.Operand is ICilLabel label && label is CilInstructionLabel cilLabel && cilLabel.Instruction != null)
                        jumpTargets.Add(cilLabel.Instruction);
                    else if (instr.Operand is IEnumerable<ICilLabel> labels) {
                        foreach (var l in labels) if (l is CilInstructionLabel cl && cl.Instruction != null) jumpTargets.Add(cl.Instruction);
                    }
                }
                foreach (var eh in body.ExceptionHandlers) {
                    if (eh.TryStart is CilInstructionLabel ts && ts.Instruction != null) jumpTargets.Add(ts.Instruction);
                    if (eh.TryEnd is CilInstructionLabel te && te.Instruction != null) jumpTargets.Add(te.Instruction);
                    if (eh.HandlerStart is CilInstructionLabel hs && hs.Instruction != null) jumpTargets.Add(hs.Instruction);
                    if (eh.HandlerEnd is CilInstructionLabel he && he.Instruction != null) jumpTargets.Add(he.Instruction);
                }

                if (isCritical) {
                    
                    
                    goto SkipModification;
                }

                 
                 
                 int mToken = method.MetadataToken.ToInt32();
                 bool isProblematic = mToken == 0x06000D7C || mToken == 0x06000045 || mToken == 0x06000005 || mToken == 0x06000007 || mToken == 0x06001329 || mToken == 0x06000C23 || mToken == 0x06000032 ||
                                    IsRangeDecoder(method) || IsControlFlowFlattened(method) || vmDispatchers.Contains(method) ||
                                    ((string?)method.Name != null && (method.Name.Contains("bin") || method.Name.Contains("Send") || method.Name.Contains("VM_Dispatcher"))) ||
                                    ((string?)method.FullName != null && (method.FullName.Contains("Disconnect") || method.FullName.Contains("Clients") || method.FullName.Contains("SetupConfig")));
                 if (isProblematic) goto SkipModification;

                
                if (body.ExceptionHandlers.Count > 0) goto SkipModification;
                
                
                if (method.Name == ".cctor" && method.DeclaringType?.Name == "<Module>") goto SkipModification;

                bool modified;
                do {
                    modified = false;
                    for (int i = 0; i < instrs.Count; i++)
                    {
                        
                        
                        
                        bool isInstanceChain = i < instrs.Count - 2 && (instrs[i].OpCode.Code == CilCode.Ldarg_0 || instrs[i].OpCode.Code == CilCode.Ldarg) && 
                                               instrs[i+1].OpCode.Code == CilCode.Ldfld;

                        int fieldStartIdx = isInstanceChain ? i + 1 : i;
                        if (i < instrs.Count - 2 && ((instrs[i].OpCode.Code == CilCode.Ldsfld || instrs[i].OpCode.Code == CilCode.Ldfld) || isInstanceChain) && 
                            (instrs[fieldStartIdx].Operand is IFieldDescriptor field) && globalDevirtMap.ContainsKey(field))
                        {
                             var devirtMap = globalDevirtMap[field];
                             
                             
                             int ldelemIndex = -1;
                             for (int j = fieldStartIdx + 1; j < Math.Min(fieldStartIdx + 30, instrs.Count); j++) {
                                 if (instrs[j].OpCode.Code == CilCode.Ldelem_Ref) {
                                     ldelemIndex = j;
                                     break;
                                 }
                                 if (instrs[j].OpCode.Code == CilCode.Ret || instrs[j].OpCode.Code == CilCode.Throw) break;
                             }
                             
                             if (ldelemIndex != -1) {
                                 try {
                                     int resolvedIndex = SimulateStackForIndex(instrs, fieldStartIdx + 1, ldelemIndex);
                                     
                                     
                                     int invokeIndex = -1;
                                     for (int k = ldelemIndex + 1; k < Math.Min(ldelemIndex + 10, instrs.Count); k++) {
                                         if ((instrs[k].OpCode.Code == CilCode.Callvirt || instrs[k].OpCode.Code == CilCode.Call) && 
                                             instrs[k].Operand is IMethodDescriptor m && (m.Name == "Invoke" || m.DeclaringType?.FullName.Contains("System.Func") == true || m.DeclaringType?.FullName.Contains("System.Action") == true)) {
                                             invokeIndex = k;
                                             break;
                                         }
                                     }

                                     if (resolvedIndex != -1 && invokeIndex != -1 && devirtMap.ContainsKey(resolvedIndex)) {
                                         var targetMethod = devirtMap[resolvedIndex];
                                         var invokeMethod = instrs[invokeIndex].Operand as IMethodDescriptor;
                                         
                                         
                                         if (targetMethod.Signature?.HasThis == true) continue;

                                         
                                         if (invokeMethod == null || !SignaturesMatch(invokeMethod, targetMethod)) continue;

                                         
                                         int nopStartIndex = i;

                                         
                                         bool hasJumpTarget = false;
                                         for (int n = nopStartIndex; n <= invokeIndex; n++) {
                                             if (jumpTargets.Contains(instrs[n])) {
                                                 hasJumpTarget = true;
                                                 break;
                                             }
                                         }
                                         if (hasJumpTarget) continue;

                                         Console.WriteLine($"[+] Devirtualized call at {method.Name} offset {instrs[i].Offset:X}: Index {resolvedIndex} -> {targetMethod.Name}");
                                         
                                         
                                         int nopEndIndex = ldelemIndex;
                                         if (ldelemIndex < instrs.Count - 1 && instrs[ldelemIndex+1].OpCode.Code == CilCode.Castclass) nopEndIndex++;
                                         
                                         if (invokeIndex <= nopEndIndex) continue; 

                                         for (int n = nopStartIndex; n <= nopEndIndex; n++) {
                                             instrs[n].OpCode = CilOpCodes.Nop;
                                             instrs[n].Operand = null;
                                         }
                                         
                                         instrs[invokeIndex].OpCode = CilOpCodes.Call;
                                         instrs[invokeIndex].Operand = targetMethod;
                                         
                                         devirtCount++;
                                         modified = true;
                                         continue;
                                     }
                                 } catch {}
                             }
                        }

                        
                        if (instrs[i].OpCode.Code == CilCode.Call && instrs[i].Operand is IMethodDescriptor proxyMethod)
                        {
                            
                            if (jumpTargets.Contains(instrs[i])) continue;
                            
                            
                            if (vmDispatchers.Contains(proxyMethod)) continue;

                            var resolvedProxy = proxyMethod.Resolve();
                            if (resolvedProxy != null && resolvedProxy.CilMethodBody != null && resolvedProxy.CilMethodBody.Instructions.Count < 15)
                            {
                                var proxyInstrs = resolvedProxy.CilMethodBody.Instructions;
                                var lastCall = proxyInstrs.LastOrDefault(ins => ins.OpCode.Code == CilCode.Call || ins.OpCode.Code == CilCode.Callvirt);
                                if (lastCall != null && lastCall.Operand is IMethodDescriptor realTarget)
                             {
                                 if (!IsObfuscatedName(realTarget.Name) || vmDispatchers.Contains(realTarget)) {
                                     
                                     if (SignaturesMatch(proxyMethod, realTarget)) {
                                         try {
                                             
                                             var defTarget = realTarget.Resolve();
                                             if (defTarget != null && IsSimpleForwarder(resolvedProxy, defTarget)) {
                                                 instrs[i].Operand = importer.ImportMethod(realTarget);
                                                 instrs[i].OpCode = lastCall.OpCode;
                                                 devirtCount++;
                                             }
                                         } catch { }
                                     }
                                 }
                             }
                            }
                        }
                    }
                } while (modified);

                for (int i = 0; i < instrs.Count; i++)
                {
                    
                    if (instrs[i].OpCode.Code == CilCode.Call && instrs[i].Operand is IMethodDescriptor strProxy)
                    {
                        
                        if (jumpTargets.Contains(instrs[i])) continue;

                        var resolvedStrProxy = strProxy.Resolve();
                        if (resolvedStrProxy != null && resolvedStrProxy.CilMethodBody != null && resolvedStrProxy.CilMethodBody.Instructions.Count < 8)
                        {
                            var proxyInstrs = resolvedStrProxy.CilMethodBody.Instructions;
                            var ldstr = proxyInstrs.FirstOrDefault(ins => ins.OpCode.Code == CilCode.Ldstr);
                            if (ldstr != null)
                            {
                                instrs[i].OpCode = CilOpCodes.Ldstr;
                                instrs[i].Operand = ldstr.Operand;
                                devirtCount++;
                            }
                        }
                    }
                }

                
                
                

                
                

                
                

                
                

                
                
                
                
                 

                 
                jumpTargets.Clear();
                foreach (var instr in instrs) {
                    if (instr.Operand is ICilLabel label && label is CilInstructionLabel cilLabel && cilLabel.Instruction != null)
                        jumpTargets.Add(cilLabel.Instruction);
                    else if (instr.Operand is IEnumerable<ICilLabel> labels) {
                        foreach (var l in labels) {
                            if (l is CilInstructionLabel cl && cl.Instruction != null)
                                jumpTargets.Add(cl.Instruction);
                        }
                    }
                }

                
                for (int i = instrs.Count - 1; i >= 0; i--) {
                    if (instrs[i].OpCode.Code == CilCode.Nop && !jumpTargets.Contains(instrs[i])) {
                        instrs.RemoveAt(i);
                    }
                    
                    else if (instrs[i].OpCode.Code == CilCode.Br || instrs[i].OpCode.Code == CilCode.Br_S) {
                        if (instrs[i].Operand is ICilLabel label && label is CilInstructionLabel cilLabel && cilLabel.Instruction != null) {
                            var targetInstr = cilLabel.Instruction;
                            if (targetInstr.OpCode.Code == CilCode.Br || targetInstr.OpCode.Code == CilCode.Br_S) {
                                instrs[i].Operand = targetInstr.Operand;
                            }
                        }
                    }
                }

                
                if (!vmDispatchers.Contains(method)) {
                    for (int i = instrs.Count - 1; i >= 0; i--) {
                        if ((instrs[i].OpCode.Code == CilCode.Ldsfld || instrs[i].OpCode.Code == CilCode.Ldfld) && 
                            i < instrs.Count - 1 && instrs[i+1].OpCode.Code == CilCode.Pop && !jumpTargets.Contains(instrs[i+1])) {
                            instrs.RemoveAt(i+1);
                            instrs.RemoveAt(i);
                        }
                    }
                }
                
                body.Instructions.CalculateOffsets();

                
                for (int h = body.ExceptionHandlers.Count - 1; h >= 0; h--)
                {
                    var handler = body.ExceptionHandlers[h];
                    bool IsValid(ICilLabel? label) => label is CilInstructionLabel cilLabel && cilLabel.Instruction != null && body.Instructions.Contains(cilLabel.Instruction);
                    if (!IsValid(handler.TryStart) || !IsValid(handler.HandlerStart)) body.ExceptionHandlers.RemoveAt(h);
                }

                SkipModification:
                
                if (IsObfuscatedName(method.Name))
                {
                    if (method.IsConstructor || method.IsRuntimeSpecialName || method.Name == "VM_Dispatcher") continue;
                    string? mName = null;
                    if (vmDispatchers.Contains(method)) mName = $"VM_Dispatcher_{method.MetadataToken.ToInt32():X}";
                    if (mName == null && methodToProp.TryGetValue((uint)method.MetadataToken.ToInt32(), out var p)) mName = p;
                    if (mName == null && methodToEv.TryGetValue((uint)method.MetadataToken.ToInt32(), out var e)) mName = e;
                    if (mName == null) mName = TryRecoverMethodNameWithXor(method, stringMap, xorKeys);

                    method.Name = mName ?? $"Method_{method.MetadataToken.ToInt32():X}";
                    
                    
                     if (IsRangeDecoder(method))
                     {
                         method.Name = $"VM_RangeDecoder_{method.MetadataToken.ToInt32():X}";
                         
                         
                         if (method.DeclaringType != null && IsObfuscatedName(method.DeclaringType.Name))
                         {
                             method.DeclaringType.Name = $"VM_Decoder_{method.DeclaringType.MetadataToken.ToInt32():X}";
                             foreach (var field in method.DeclaringType.Fields)
                             {
                                 if (IsObfuscatedName(field.Name))
                                 {
                                     
                                     
                                     if (field.Signature?.FieldType.FullName.Contains("Stream") == true)
                                         field.Name = "VM_Stream";
                                     else if (field.Signature?.FieldType.FullName.Contains("UInt32") == true)
                                     {
                                         
                                         if (field.Name!.ToString().Length > 0) 
                                             field.Name = $"VM_Field_{field.MetadataToken.ToInt32():X}";
                                     }
                                 }
                             }
                         }
                     }

                     
                     if (IsControlFlowFlattened(method))
                     {
                         method.Name = $"VM_Dispatcher_{method.MetadataToken.ToInt32():X}";
                         vmDispatchers.Add(method);
                         
                         
                         try { EmulateVMPControlFlow(method); } catch {}
                     }

                     
                     if (IsConstantLoader(method))
                     {
                         method.Name = $"VM_ConstantLoader_{method.MetadataToken.ToInt32():X}";
                     }

                     
                     if (IsRC4(method))
                     {
                         method.Name = $"VM_RC4_Decrypt_{method.MetadataToken.ToInt32():X}";
                     }

                    methodCount++;
                }
            }
        }

        
        Console.WriteLine("Performing advanced junk removal...");
        foreach (var type in module.GetAllTypes())
        {
            for (int i = type.Methods.Count - 1; i >= 0; i--)
            {
                var m = type.Methods[i];
                if (m.CilMethodBody != null && m.CilMethodBody.Instructions.Count <= 2)
                {
                    var instrs = m.CilMethodBody.Instructions;
                     
                     
                     bool isJunk = instrs.All(ins => 
                         ins.OpCode.Code == CilCode.Nop || 
                         ins.OpCode.Code == CilCode.Ret ||
                         (ins.OpCode.Code >= CilCode.Ldc_I4_M1 && ins.OpCode.Code <= CilCode.Ldc_I4_8) ||
                         ins.OpCode.Code == CilCode.Ldc_I4 || 
                         ins.OpCode.Code == CilCode.Ldc_I4_S ||
                         ins.OpCode.Code == CilCode.Ldnull ||
                         IsLdarg(ins.OpCode.Code) ||
                         ins.OpCode.Code == CilCode.Pop
                     );
                     
                     
                     if (!isJunk && instrs.Count < 5)
                     {
                         if (instrs.Any(ins => ins.OpCode.Code == CilCode.Throw || ins.OpCode.Code == CilCode.Newobj))
                             isJunk = true;
                     }
                    
                    if (isJunk)
                    {
                        if (m.IsConstructor || m.IsRuntimeSpecialName || m.IsVirtual) continue;
                         if (m == module.ManagedEntrypoint) continue;
                         if (m.Name == "Main") continue;
                         
                         
                         if (m.IsNewSlot || m.IsAbstract) continue;
                         
                          if (type.MethodImplementations.Any(impl => impl.Body == m)) continue;
                          if (type.Interfaces.Any() && !m.IsStatic && m.IsVirtual) continue; 
                          
                          if (m.Name == "Dispose" || m.Name == "get_IsAvailable" || m.Name == "Close" || m.Name == "ToString") continue;
  
                         
                         
                         
                     }
                 }
             }
         }

         
         Console.WriteLine("Removing calls to VM Dispatchers...");
         foreach (var type in module.GetAllTypes())
         {
             foreach (var method in type.Methods)
             {
                 
                 if (method.Name == ".cctor" && method.DeclaringType?.Name == "<Module>") continue;

                 if (method.CilMethodBody == null) continue;
                 var instrs = method.CilMethodBody.Instructions;
                 bool modified = false;
                 for (int i = 0; i < instrs.Count; i++)
                 {
                     if ((instrs[i].OpCode.Code == CilCode.Call || instrs[i].OpCode.Code == CilCode.Callvirt) && 
                         instrs[i].Operand is MethodDefinition target && vmDispatchers.Contains(target))
                     {
                         instrs[i].OpCode = CilOpCodes.Nop;
                         instrs[i].Operand = null;
                         modified = true;
                     }
                 }
             }
         }

         
        Console.WriteLine("Skipping removal of empty types (User Request)...");
        var typesToRemove = new List<TypeDefinition>();
        
        
        void ScanForEmptyTypes(TypeDefinition type)
        {
            
            for (int i = type.NestedTypes.Count - 1; i >= 0; i--)
            {
                ScanForEmptyTypes(type.NestedTypes[i]);
            }
            
            
            if (IsTypeEmpty(type) && type.Name != "<Module>" && (module.ManagedEntrypoint == null || type != (module.ManagedEntrypoint as MethodDefinition)?.DeclaringType))
            {
                
                typesToRemove.Add(type);
            }
        }

        
        
        
        
        

        foreach (var type in typesToRemove)
         {
             if (type.IsNested && type.DeclaringType != null)
             {
                 Console.WriteLine($"[-] Removing empty nested type: {type.DeclaringType.Name}+{type.Name}");
                 type.DeclaringType.NestedTypes.Remove(type);
             }
             else
             {
                 Console.WriteLine($"[-] Removing empty type: {type.FullName}");
                 module.TopLevelTypes.Remove(type);
             }
         }
         
         
          Console.WriteLine("Skipping removal of unused fields/properties (User Request)...");
          

         
         Console.WriteLine("Performing aggressive junk type removal...");
         var globallyUsedTypes = new HashSet<int>();
         
         
         if (module.ManagedEntrypointMethod != null && module.ManagedEntrypointMethod.DeclaringType != null) 
             globallyUsedTypes.Add(module.ManagedEntrypointMethod.DeclaringType.MetadataToken.ToInt32());
         var moduleType = module.TopLevelTypes.FirstOrDefault(t => t.Name == "<Module>");
         if (moduleType != null) globallyUsedTypes.Add(moduleType.MetadataToken.ToInt32());
             
         foreach (var type in module.GetAllTypes()) {
             
             if (type.BaseType != null) { var r = type.BaseType.Resolve(); if(r != null && r.Module == module && r != type) globallyUsedTypes.Add(r.MetadataToken.ToInt32()); }
             foreach (var impl in type.Interfaces) { var r = impl.Interface?.Resolve(); if(r != null && r.Module == module && r != type) globallyUsedTypes.Add(r.MetadataToken.ToInt32()); }
             
             
             foreach (var f in type.Fields) {
                 var r = f.Signature?.FieldType?.Resolve(); 
                 if (r != null && r.Module == module && r != type) globallyUsedTypes.Add(r.MetadataToken.ToInt32());
             }
             
             
             foreach (var m in type.Methods) {
                 if (m.Signature != null) {
                    var r = m.Signature.ReturnType?.Resolve();
                    if (r != null && r.Module == module && r != type) globallyUsedTypes.Add(r.MetadataToken.ToInt32());
                    foreach (var p in m.Signature.ParameterTypes) {
                        r = p.Resolve();
                        if (r != null && r.Module == module && r != type) globallyUsedTypes.Add(r.MetadataToken.ToInt32());
                    }
                 }
                 
                 if (m.CilMethodBody != null) {
                     foreach (var l in m.CilMethodBody.LocalVariables) {
                         var r = l.VariableType?.Resolve();
                         if (r != null && r.Module == module && r != type) globallyUsedTypes.Add(r.MetadataToken.ToInt32());
                     }
                     foreach (var instr in m.CilMethodBody.Instructions) {
                         TypeDefinition? dep = null;
                         if (instr.Operand is ITypeDefOrRef tdr) dep = tdr.Resolve();
                         else if (instr.Operand is IMethodDefOrRef mdr) dep = mdr.DeclaringType?.Resolve();
                         else if (instr.Operand is IFieldDescriptor fd) dep = fd.DeclaringType?.Resolve();
                         
                         if (dep != null && dep.Module == module && dep != type) globallyUsedTypes.Add(dep.MetadataToken.ToInt32());
                     }
                     foreach (var eh in m.CilMethodBody.ExceptionHandlers) {
                         var r = eh.ExceptionType?.Resolve();
                         if (r != null && r.Module == module && r != type) globallyUsedTypes.Add(r.MetadataToken.ToInt32());
                     }
                 }
             }
         }
         
         
         int removedJunkCount = 0;
         for (int i = module.TopLevelTypes.Count - 1; i >= 0; i--) {
             var t = module.TopLevelTypes[i];
             if (t.Name == "<Module>" || (module.ManagedEntrypointMethod != null && t == module.ManagedEntrypointMethod.DeclaringType)) continue;
             
             if (!globallyUsedTypes.Contains(t.MetadataToken.ToInt32())) {
                 
                 bool isJunkName = t.Name.ToString().StartsWith("Type_") || IsObfuscatedName(t.Name.ToString()) || t.Name.ToString().Length < 3;
                 bool isVMType = vmDispatchers.Any(vm => vm.DeclaringType == t) || t.Name == "GetTypeFromHandle";
                 
                 if (isJunkName || isVMType) {
                      
                      if (t.BaseType == null || !t.BaseType.FullName.Contains("System.Windows.Forms")) {
                          
                          
                          
                          
                          
                          if (isVMType) {
                              t.Name = "VM_Engine_" + t.MetadataToken.ToInt32().ToString("X");
                              t.Namespace = "VMUnprotect.Runtime";
                          } else {
                              
                              
                          }
                      }
                  }
             }
         }
         
         
         
         Console.WriteLine("Performing intelligent renaming...");
         foreach (var type in module.GetAllTypes()) {
             if (type.Name.ToString().StartsWith("Type_") || IsObfuscatedName(type.Name.ToString()) || type.Name.ToString().StartsWith("VM_Engine_")) {
                 
                 var potentialNames = new HashSet<string>();
                 foreach (var m in type.Methods) {
                     if (m.CilMethodBody != null) {
                         foreach (var instr in m.CilMethodBody.Instructions) {
                             if (instr.OpCode.Code == CilCode.Ldstr && instr.Operand is string s) {
                                 
                                 if (s.Contains("Form1")) potentialNames.Add("Form1");
                                 if (s.Contains("Settings")) potentialNames.Add("SettingsManager");
                                 if (s.Contains("Clients")) potentialNames.Add("ClientManager");
                                 if (s.Contains("Clipper")) potentialNames.Add("Clipper");
                                 if (s.Contains("Miner")) potentialNames.Add("Miner");
                                 if (s.Contains("Builder")) potentialNames.Add("Builder");
                                 
                             }
                         }
                     }
                 }
                 
                 if (potentialNames.Count > 0) {
                     string newName = potentialNames.First() + "_" + type.MetadataToken.ToInt32().ToString("X");
                     type.Name = newName;
                 }
                 
                 
                 if (vmDispatchers.Any(vm => vm.DeclaringType == type) || type.Name == "GetTypeFromHandle") {
                     type.Name = "VM_Core_" + type.MetadataToken.ToInt32().ToString("X");
                     type.Namespace = "VM.Runtime";
                 }
             }
         }

         
        Console.WriteLine("Performing final metadata fixup...");
        
        var allModuleTypes = module.GetAllTypes().ToList();
        var typeTokenSet = new HashSet<int>(allModuleTypes.Select(t => t.MetadataToken.ToInt32()));
        var methodTokenSet = new HashSet<int>(allModuleTypes.SelectMany(t => t.Methods).Select(m => m.MetadataToken.ToInt32()));
        var fieldTokenSet = new HashSet<int>(allModuleTypes.SelectMany(t => t.Fields).Select(f => f.MetadataToken.ToInt32()));

        foreach (var type in allModuleTypes)
        {
            
            
            type.CustomAttributes.Clear();
            if (type.BaseType != null) {
                 try { type.BaseType = importer.ImportType(type.BaseType); } catch { type.BaseType = importer.ImportType(module.CorLibTypeFactory.Object.Type); }
             }
            
            for (int i = 0; i < type.Interfaces.Count; i++) {
                try { type.Interfaces[i].Interface = importer.ImportType(type.Interfaces[i].Interface); } catch { }
            }
            
            
             var impls = type.MethodImplementations.ToList();
             type.MethodImplementations.Clear();
             foreach (var impl in impls) {
                 try {
                     var importedBody = importer.ImportMethod(impl.Body);
                     var importedDecl = importer.ImportMethod(impl.Declaration);
                     type.MethodImplementations.Add(new MethodImplementation(importedDecl, importedBody));
                 } catch {
                     
                     
                     
                     
                 }
             }

            foreach (var field in type.Fields) {
                field.CustomAttributes.Clear();
                
            }

            foreach (var method in type.Methods) {
                if (method.IsPInvokeImpl) method.ImplementationMap = null;
                method.CustomAttributes.Clear();
                method.SecurityDeclarations.Clear();
                
                try { if (method.Signature != null) method.Signature = importer.ImportMethodSignature(method.Signature); } catch { }
                
                if (method.CilMethodBody != null) {
                    
                    
                    int currentToken = method.MetadataToken.ToInt32();
                    bool isVMMethod = vmDispatchers.Any(vm => vm.MetadataToken.ToInt32() == currentToken) || 
                                      (type.Name.ToString() == "GetTypeFromHandle") || 
                                      (method.Name.ToString().Contains("VM_Dispatcher"));

                    if (isVMMethod) {
                         
                         method.CilMethodBody.Instructions.Clear();
                         method.CilMethodBody.ExceptionHandlers.Clear();
                         method.CilMethodBody.LocalVariables.Clear();
                         
                         if (method.Signature.ReturnType.ElementType != ElementType.Void) {
                             if (method.Signature.ReturnType.IsValueType) {
                                 var local = new CilLocalVariable(method.Signature.ReturnType);
                                 method.CilMethodBody.LocalVariables.Add(local);
                                 method.CilMethodBody.Instructions.Add(CilOpCodes.Ldloca, local);
                                 method.CilMethodBody.Instructions.Add(CilOpCodes.Initobj, importer.ImportType(method.Signature.ReturnType.ToTypeDefOrRef()));
                                 method.CilMethodBody.Instructions.Add(CilOpCodes.Ldloc, local);
                             } else {
                                 method.CilMethodBody.Instructions.Add(CilOpCodes.Ldnull);
                             }
                         }
                         method.CilMethodBody.Instructions.Add(CilOpCodes.Ret);
                         
                         
                         continue; 
                    }

                    
                    
                    
                    
                    
                    if (method.IsConstructor && method.IsStatic && method.Name == ".cctor" && method.DeclaringType?.Name == "<Module>") {
                         
                         
                         
                         
                         
                         continue; 
                    }

                    
                    if (method.CilMethodBody.MaxStack < 8) method.CilMethodBody.MaxStack = 8;
                    if (method.CilMethodBody.MaxStack > 100) method.CilMethodBody.MaxStack = 128; 

                    
                    
                    try
                    {
                        method.CilMethodBody.ComputeMaxStack();
                    }
                    catch (Exception)
                    {
                        Console.WriteLine($"[!] Detected stack imbalance in {method.FullName}. Sanitizing method body to allow save.");
                        method.CilMethodBody.Instructions.Clear();
                        method.CilMethodBody.ExceptionHandlers.Clear();
                        method.CilMethodBody.LocalVariables.Clear();
                        
                        if (method.Signature.ReturnType.ElementType != ElementType.Void)
                        {
                            if (method.Signature.ReturnType.IsValueType)
                            {
                                var local = new CilLocalVariable(method.Signature.ReturnType);
                                method.CilMethodBody.LocalVariables.Add(local);
                                method.CilMethodBody.Instructions.Add(CilOpCodes.Ldloca, local);
                                method.CilMethodBody.Instructions.Add(CilOpCodes.Initobj, importer.ImportType(method.Signature.ReturnType.ToTypeDefOrRef()));
                                method.CilMethodBody.Instructions.Add(CilOpCodes.Ldloc, local);
                            }
                            else
                            {
                                method.CilMethodBody.Instructions.Add(CilOpCodes.Ldnull);
                            }
                        }
                        method.CilMethodBody.Instructions.Add(CilOpCodes.Ret);
                        method.CilMethodBody.MaxStack = 8;
                        continue;
                    }

                    foreach (var local in method.CilMethodBody.LocalVariables) {
                        try { local.VariableType = importer.ImportTypeSignature(local.VariableType); } catch { }
                    }

                    foreach (var instr in method.CilMethodBody.Instructions) {
                        try {
                            if (instr.Operand is IMethodDescriptor m) {
                                if (m is MethodSpecification spec) {
                                    spec.Method = importer.ImportMethod(spec.Method);
                                    for (int j = 0; j < spec.Signature.TypeArguments.Count; j++)
                                        spec.Signature.TypeArguments[j] = importer.ImportTypeSignature(spec.Signature.TypeArguments[j]);
                                } else if (m is MethodDefinition def && methodTokenSet.Contains(def.MetadataToken.ToInt32())) {
                                    instr.Operand = def;
                                } else if (m is IMethodDefOrRef mdr) {
                                    
                                    if (mdr is MethodDefinition ghostDef && !methodTokenSet.Contains(ghostDef.MetadataToken.ToInt32()))
                                    {
                                        
                                        try
                                        {
                                            var resolvedMethod = assembly.ManifestModule.ResolveMethod(ghostDef.MetadataToken.ToInt32());
                                            if (resolvedMethod != null)
                                            {
                                                instr.Operand = importer.ImportMethod(resolvedMethod);
                                                continue;
                                            }
                                        }
                                        catch { }
                                        
                                        
                                         
                                         bool resolved = false;
                                         if (ghostDef.DeclaringType != null && ghostDef.DeclaringType.Module?.Assembly?.Name?.Contains("mscorlib") == true) {
                                              try {
                                                  var runtimeType = Type.GetType(ghostDef.DeclaringType.FullName ?? "");
                                                  if (runtimeType != null) {
                                                      var runtimeMethod = runtimeType.GetMethod(ghostDef.Name ?? "", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static);
                                                      if (runtimeMethod != null) {
                                                          instr.Operand = importer.ImportMethod(runtimeMethod);
                                                          resolved = true;
                                                          continue;
                                                      }
                                                  }
                                              } catch {}
                                         }
                                         
                                         
                                         
                                         
                                         if (!resolved)
                                         {
                                              try {
                                                  instr.Operand = importer.ImportMethod(ghostDef);
                                                  continue;
                                              } catch {}
                                         }
                                     }
                                     instr.Operand = importer.ImportMethod(mdr);
                                }
                            }
                            else if (instr.Operand is IFieldDescriptor f) {
                                if (f is FieldDefinition def && fieldTokenSet.Contains(def.MetadataToken.ToInt32())) {
                                    instr.Operand = def;
                                } else {
                                    instr.Operand = importer.ImportField(f);
                                }
                            }
                            else if (instr.Operand is ITypeDefOrRef t) {
                                if (t is TypeSpecification spec) {
                                    spec.Signature = importer.ImportTypeSignature(spec.Signature);
                                } else if (t is TypeDefinition def && typeTokenSet.Contains(def.MetadataToken.ToInt32())) {
                                    instr.Operand = def;
                                } else {
                                    instr.Operand = importer.ImportType(t);
                                }
                            }
                        } catch { }
                    }

                    foreach (var handler in method.CilMethodBody.ExceptionHandlers) {
                        if (handler.HandlerType == CilExceptionHandlerType.Exception && handler.ExceptionType != null) {
                            try { handler.ExceptionType = importer.ImportType(handler.ExceptionType); } catch { }
                        }
                    }
                }
            }
        }

        
        ZeroOutVMData(module);

        string renamedPath = dumpedPath.Replace(".exe", "-renamed.exe");
        try {
            try {
                Console.WriteLine("Saving module...");
                
                module.Write(renamedPath);
            } catch (Exception ex) {
                Console.WriteLine($"[!] Standard save failed: {ex.Message}");
                Console.WriteLine("Attempting aggressive rebuild with ManagedPEImageBuilder...");
                try {
                    var imageBuilder = new ManagedPEImageBuilder();
                    
                    
                    module.Write(renamedPath, imageBuilder);
                } catch (Exception ex2) {
                    Console.WriteLine($"[FATAL] Aggressive save failed: {ex2.Message}");
                    if (ex2.InnerException != null) {
                        Console.WriteLine($"Inner Error: {ex2.InnerException.Message}");
                    }
                }
            }
            
            var fi = new FileInfo(renamedPath);
            if (fi.Exists && fi.Length > 0)
                Console.WriteLine($"\n[+] Renamed {typeCount} types, {methodCount} methods. Devirtualized {devirtCount} proxy calls. Saved to {renamedPath} ({fi.Length / 1024} KB)");
            else
                Console.WriteLine("\n[ERROR] Renamed file is 0 bytes or missing!");
        } catch (Exception ex) {
            Console.WriteLine($"\n[ERROR] Final save failed: {ex.Message}");
            if (ex.InnerException != null) Console.WriteLine($"Inner: {ex.InnerException.Message}");
        }
    }

    static bool IsModuleType(TypeDefinition type) => type.Name == "<Module>";

    static bool IsObfuscatedName(string? name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        if (name.Length >= 6 && name.Length <= 12 && name.All(c => "0123456789ABCDEFabcdef".Contains(c))) return true;
        if (name.Any(c => c < 32 || c > 126)) return true;
        if (name.Length > 40) return true;
        return false;
    }

    static bool SignaturesMatch(IMethodDescriptor m1, IMethodDescriptor m2)
    {
        if (m1 == null || m2 == null) return false;
        try {
            var s1 = m1.Signature;
            var s2 = m2.Signature;
            if (s1 == null || s2 == null) return false;

            var comparer = new SignatureComparer();

            
            if (!comparer.Equals(s1.ReturnType, s2.ReturnType)) return false;

            
            
            if (s1.HasThis && !s2.HasThis) {
                
                if (s1.ParameterTypes.Count != s2.ParameterTypes.Count) return false;
                for (int i = 0; i < s1.ParameterTypes.Count; i++) {
                    if (!comparer.Equals(s1.ParameterTypes[i], s2.ParameterTypes[i])) return false;
                }
                return true;
            }

            
            if (!s1.HasThis && !s2.HasThis) {
                if (s1.ParameterTypes.Count != s2.ParameterTypes.Count) return false;
                for (int i = 0; i < s1.ParameterTypes.Count; i++) {
                    if (!comparer.Equals(s1.ParameterTypes[i], s2.ParameterTypes[i])) return false;
                }
                return true;
            }

            
            if (s1.HasThis && s2.HasThis) {
                if (s1.ParameterTypes.Count != s2.ParameterTypes.Count) return false;
                for (int i = 0; i < s1.ParameterTypes.Count; i++) {
                    if (!comparer.Equals(s1.ParameterTypes[i], s2.ParameterTypes[i])) return false;
                }
                return true;
            }

            
            if (!s1.HasThis && s2.HasThis && s1.ParameterTypes.Count == s2.ParameterTypes.Count + 1) {
                for (int i = 0; i < s2.ParameterTypes.Count; i++) {
                    if (!comparer.Equals(s1.ParameterTypes[i+1], s2.ParameterTypes[i])) return false;
                }
                return true;
            }

            return false;
        } catch { return false; }
    }

    static bool IsSimpleForwarder(MethodDefinition proxy, MethodDefinition target)
    {
        if (proxy.CilMethodBody == null) return false;
        var instrs = proxy.CilMethodBody.Instructions;
        
        int targetStackArgs = target.Signature.ParameterTypes.Count;
        if (target.Signature.HasThis && !target.Signature.ExplicitThis) targetStackArgs++;

        var forwardInstrs = new List<CilInstruction>();
        foreach(var instr in instrs) {
            if (instr.OpCode.Code == CilCode.Call || instr.OpCode.Code == CilCode.Callvirt) {
                if (instr.Operand is IMethodDescriptor m) {
                     var resolved = m.Resolve();
                     if (resolved == target) break; 
                }
            }
            if (instr.OpCode.Code == CilCode.Nop) continue;
            forwardInstrs.Add(instr);
        }
        
        if (forwardInstrs.Count != targetStackArgs) return false;
        
        for(int i=0; i<forwardInstrs.Count; i++) {
             if (!IsLdarg(forwardInstrs[i].OpCode.Code)) return false;
        }
        return true;
    }

    static bool IsLdarg(CilCode code) {
        return code == CilCode.Ldarg || code == CilCode.Ldarg_0 || code == CilCode.Ldarg_1 || 
               code == CilCode.Ldarg_2 || code == CilCode.Ldarg_3 || code == CilCode.Ldarg_S;
    }

    static bool IsRangeDecoder(MethodDefinition method)
    {
        if (method.CilMethodBody == null) return false;
        var instrs = method.CilMethodBody.Instructions;
        
        bool hasReadByte = false;
        bool hasNormalizer = false;
        bool hasBitShift31 = false;
        bool hasBitwiseLoop = false;
        
        foreach (var instr in instrs)
        {
            if (instr.OpCode.Code == CilCode.Callvirt || instr.OpCode.Code == CilCode.Call)
            {
                if (instr.Operand is IMethodDescriptor m && (m.Name == "ReadByte" || m.Name == "Read"))
                    hasReadByte = true;
            }
            
            if (instr.IsLdcI4())
            {
                int? val = GetLdcI4Value(instr);
                if (val == 16777216) hasNormalizer = true; 
                if (val == 31) hasBitShift31 = true;
            }
            
            if (instr.OpCode.Code == CilCode.Ble || instr.OpCode.Code == CilCode.Blt || 
                instr.OpCode.Code == CilCode.Ble_S || instr.OpCode.Code == CilCode.Blt_S)
                hasBitwiseLoop = true;
        }
        
        
         return hasNormalizer && (hasReadByte || hasBitShift31) && hasBitwiseLoop;
     }

     static bool IsControlFlowFlattened(MethodDefinition method)
     {
         if (method.CilMethodBody == null) return false;
         var instrs = method.CilMethodBody.Instructions;
         
         bool hasSwitch = false;
         bool hasLoop = false;
         int jumpBackCount = 0;
         
         foreach (var instr in instrs)
         {
             if (instr.OpCode.Code == CilCode.Switch) hasSwitch = true;
             
             
             if (instr.OpCode.Code == CilCode.Br || instr.OpCode.Code == CilCode.Br_S)
             {
                 if (instr.Operand is ICilLabel label && label is CilInstructionLabel cilLabel && cilLabel.Instruction != null)
                 {
                     if (cilLabel.Instruction.Offset < instr.Offset)
                         jumpBackCount++;
                 }
             }
         }
         
         if (jumpBackCount > 0) hasLoop = true;
         
         
          return (hasSwitch && hasLoop) || jumpBackCount > 5;
      }

      static bool IsConstantLoader(MethodDefinition method)
      {
          if (method.CilMethodBody == null) return false;
          var instrs = method.CilMethodBody.Instructions;
          
          bool hasList = false;
          bool hasStream = false;
          bool hasToArray = false;
          bool hasSwitch = false;
          
          foreach (var instr in instrs)
          {
              if (instr.Operand is ITypeDefOrRef t)
              {
                  if (t.FullName.Contains("System.Collections.Generic.List") || t.FullName.Contains("System.Collections.ArrayList"))
                      hasList = true;
                  if (t.FullName.Contains("System.IO.MemoryStream") || t.FullName.Contains("System.IO.Stream"))
                      hasStream = true;
              }
              if (instr.Operand is IMethodDescriptor m)
              {
                  if (m.Name == "ToArray") hasToArray = true;
              }
              if (instr.OpCode.Code == CilCode.Switch) hasSwitch = true;
          }
          
          return hasList && hasStream && (hasToArray || hasSwitch);
      }

      static bool IsRC4(MethodDefinition method)
      {
          if (method.CilMethodBody == null) return false;
          var instrs = method.CilMethodBody.Instructions;
          
          bool has256 = false;
          bool hasSwap = false;
          bool hasXor = false;
          bool hasModulo256 = false;
          
          foreach (var instr in instrs)
          {
              if (instr.IsLdcI4() && GetLdcI4Value(instr) == 256) has256 = true;
              if (instr.OpCode.Code == CilCode.Xor) hasXor = true;
              if (instr.OpCode.Code == CilCode.Rem || (instr.IsLdcI4() && GetLdcI4Value(instr) == 255)) hasModulo256 = true;
          }
          
          
          
          return has256 && hasXor && (hasModulo256 || instrs.Count > 50);
      }
  
      static List<string> DiscoverXorKeys(ModuleDefinition module)
    {
        var keys = new List<string>();
        foreach (var type in module.GetAllTypes())
        {
            foreach (var method in type.Methods)
            {
                if (method.CilMethodBody == null) continue;
                foreach (var instr in method.CilMethodBody.Instructions)
                {
                    if (instr.OpCode.Code == CilCode.Ldstr && instr.Operand is string s && s.Length > 40)
                    {
                        if (s.Count(c => !char.IsLetterOrDigit(c)) > 10 && !keys.Contains(s)) keys.Add(s);
                    }
                }
            }
        }
        return keys.OrderByDescending(k => k.Length).ToList();
    }

    static string DecryptSnatString(string? input, List<string> keys)
    {
        if (string.IsNullOrEmpty(input)) return input ?? "";
        
        var allKeys = new List<string>(keys) {
            "kws~ZYzv7jPJB2rW`u03$IK>O!+'iyacl/bLN={TVQ#6M%]h8g<d1p[^)?4.eSR@:oXEm\\ (5_AF|;*-\"tDnHC9Ux&,Gq}f",
            "rY=V4!*LWIzt8_ (lm@}Z)\\^B%qCosRU0gO'F\"NS#jHev9{b,AaTdc~75w$fKG>2|<hp16./X-QD`u&iE+kyJ;M?xnP]:3["
        };
        foreach (var key in allKeys)
        {
            try {
                byte[] data = Convert.FromBase64String(input!);
                byte[] kb = Encoding.UTF8.GetBytes(key);
                byte[] res = new byte[data.Length];
                for (int i = 0; i < data.Length; i++) res[i] = (byte)(data[i] ^ kb[i % kb.Length]);
                string s = Encoding.UTF8.GetString(res).Trim('\0');
                if (s.Length > 3 && !IsObfuscatedName(s)) return s;
            } catch { }
        }
        return input!;
    }

    static string? TryRecoverName(TypeDefinition type, Dictionary<string, List<string>> stringMap)
    {
        
        foreach (var ctor in type.Methods.Where(m => m.IsConstructor))
        {
            if (ctor.CilMethodBody == null) continue;
            foreach (var instr in ctor.CilMethodBody.Instructions)
            {
                if (instr.OpCode.Code == CilCode.Ldstr && instr.Operand is string s)
                {
                    
                    if (s.Contains("Plugin\\Desktop.dll")) return "DesktopModule";
                    if (s.Contains("Plugin\\Camera.dll")) return "CameraModule";
                    if (s.Contains("Plugin\\Microphone.dll")) return "MicrophoneModule";
                    if (s.Contains("Plugin\\KeyLogger.dll")) return "KeyLoggerModule";
                    if (s.Contains("Plugin\\Process.dll")) return "ProcessManager";
                    if (s.Contains("Plugin\\AutoRun.dll")) return "AutoRunManager";
                    if (s.Contains("Plugin\\Netstat.dll")) return "NetstatManager";
                    if (s.Contains("Plugin\\Shell.dll")) return "ShellManager";
                    if (s.Contains("Plugin\\Regedit.dll")) return "RegeditManager";
                    if (s.Contains("Plugin\\HVNC.dll")) return "HVNCModule";
                    if (s.Contains("Plugin\\Fun.dll")) return "FunModule";
                    if (s.Contains("Plugin\\Chat.dll")) return "ChatModule";
                    if (s.Contains("Plugin\\Service.dll")) return "ServiceManager";
                    if (s.Contains("Plugin\\Audio.dll")) return "AudioModule";
                    if (s.Contains("Plugin\\Clipper.dll")) return "ClipperModule";
                    if (s.Contains("Plugin\\BotKiller.dll")) return "BotKillerModule";
                    if (s.Contains("Plugin\\BotSpeaker.dll")) return "BotSpeakerModule";
                    if (s.Contains("Plugin\\Clipboard.dll")) return "ClipboardManager";
                    if (s.Contains("Plugin\\DDos.dll")) return "DDosModule";
                    if (s.Contains("Plugin\\DeviceManager.dll")) return "DeviceManager";
                    if (s.Contains("Plugin\\Explorer.dll")) return "ExplorerManager";
                    if (s.Contains("Plugin\\FileSearcher.dll")) return "FileSearcher";
                    if (s.Contains("Plugin\\HostsFile.dll")) return "HostsFileManager";
                    if (s.Contains("Plugin\\Injector.dll")) return "InjectorModule";
                    if (s.Contains("Plugin\\MinerEtc.dll")) return "MinerEtcModule";
                    if (s.Contains("Plugin\\MinerRigel.dll")) return "MinerRigelModule";
                    if (s.Contains("Plugin\\MinerXMR.dll")) return "MinerXMRModule";
                    if (s.Contains("Plugin\\Notepad.dll")) return "NotepadModule";
                    if (s.Contains("Plugin\\Performance.dll")) return "PerformanceMonitor";
                    if (s.Contains("Plugin\\Programs.dll")) return "ProgramsManager";
                    if (s.Contains("Plugin\\ReportWindow.dll")) return "ReportWindowManager";
                    if (s.Contains("Plugin\\ReverseProxy.dll")) return "ReverseProxyModule";
                    if (s.Contains("Plugin\\SendFile.dll")) return "SendFileModule";
                    if (s.Contains("Plugin\\Stealer1.dll")) return "StealerModuleV1";
                    if (s.Contains("Plugin\\Stealer2.dll")) return "StealerModuleV2";
                    if (s.Contains("Plugin\\StealthSaver.dll")) return "StealthSaverModule";
                    if (s.Contains("Plugin\\SysPlug.dll")) return "SysPlugModule";
                    if (s.Contains("Plugin\\SystemSound.dll")) return "SystemSoundModule";
                    if (s.Contains("Plugin\\UAC.dll")) return "UACBypass";
                    if (s.Contains("Plugin\\Volume.dll")) return "VolumeControl";
                    if (s.Contains("Plugin\\Window.dll")) return "WindowManager";
                    if (s.Contains("Plugin\\Worm.dll")) return "WormModule";

                    if (s.Contains("local\\Settings.json")) return "Settings";
                    if (s.Contains("local\\Tasks.json")) return "TaskManager";
                    if (s.Contains("local\\Clipper.json")) return "ClipperConfig";
                    if (s.Contains("local\\Miner.json")) return "MinerConfig";
                    if (s.Contains("local\\Bulider.json")) return "BuilderConfig";

                    
                    if (s.Contains("Form1") && type.BaseType != null && type.BaseType.FullName.Contains("Form")) return "Form1";
                    if (s.Contains("Clients") && type.Fields.Any(f => f.Signature?.FieldType.FullName.Contains("TcpClient") ?? false)) return "Clients";

                    if (s.Contains("Select * From Win32_")) return "WmiQuery";
                    if (s.Contains("cmd.exe /c")) return "CommandExecutor";

                    if (s.Contains(".") && s.Length > 5 && s.All(c => char.IsLetterOrDigit(c) || c == '.' || c == '_'))
                        return s.Split('.').Last();
                    
                    if (s.Length > 3 && s.Length < 32 && char.IsUpper(s[0]) && s.All(c => char.IsLetterOrDigit(c) || c == '_'))
                        return s;
                }
            }
        }

        
        if (type.BaseType != null)
        {
            string baseName = type.BaseType.Name ?? "";
            string baseFullName = type.BaseType.FullName ?? "";

            if (baseFullName.Contains("System.Windows.Forms.Form")) return "Form_" + type.MetadataToken.ToInt32().ToString("X");
            if (baseFullName.Contains("System.Windows.Forms.UserControl")) return "UserControl_" + type.MetadataToken.ToInt32().ToString("X");
            if (baseFullName.Contains("System.Configuration.ApplicationSettingsBase")) return "Settings_" + type.MetadataToken.ToInt32().ToString("X");
            if (baseFullName.Contains("System.Resources.ResourceManager")) return "Resources_" + type.MetadataToken.ToInt32().ToString("X");
            if (baseFullName.Contains("System.Windows.Forms.ApplicationContext")) return "AppContext_" + type.MetadataToken.ToInt32().ToString("X");
        }

        
        if (type.Fields.Any(f => f.Name.Contains("components") && f.Signature != null && f.Signature.FieldType.FullName.Contains("IContainer")))
            return "Component_" + type.MetadataToken.ToInt32().ToString("X");

        return null;
    }

    static string? TryRecoverMethodNameWithXor(MethodDefinition method, Dictionary<string, List<string>> stringMap, List<string> xorKeys)
    {
        if (method.CilMethodBody == null) return null;
        
        
        if (method.Name == "Main" || (method.Signature != null && method.Signature.ParameterTypes.Count == 1 && method.Signature.ParameterTypes[0].FullName.Contains("String[]"))) return "Main";

        foreach (var instr in method.CilMethodBody.Instructions)
        {
            if (instr.OpCode.Code == CilCode.Ldstr && instr.Operand is string s)
            {
                string dec = DecryptSnatString(s, xorKeys);
                
                
                if (dec.Contains("Error") && dec.Contains("Log")) return "LogError";
                if (dec.Contains("Connected")) return "OnConnected";
                if (dec.Contains("Disconnected")) return "OnDisconnected";
                if (dec.Contains("Ping")) return "SendPing";
                if (dec.Contains("Pong")) return "ReceivePong";
                
                if (dec.Contains(".") && dec.Length > 8 && !dec.Contains(" ")) return dec.Split('.').Last();
                
                string[] p = { "Run", "Setup", "Infect", "Bypass", "Check", "Payload", "Driver", "Wmi", "Amsi", "Etw", "Main", "Form1_Load", "InitializeComponent", "Dispose" };
                foreach (var pattern in p) if (dec.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0) return pattern + "_" + method.MetadataToken.ToInt32().ToString("X");
            }
        }

        return null;
    }
    
    
    static int SimulateStackForIndex(IList<CilInstruction> instrs, int startIndex, int endIndex, Dictionary<int, int>? localConstants = null)
    {
        
        var stack = new Stack<int>();
        
        for (int i = startIndex; i < endIndex; i++) {
            var op = instrs[i].OpCode.Code;
            
            if (instrs[i].IsLdcI4()) {
                stack.Push(GetLdcI4Value(instrs[i]) ?? 0);
            }
            else if (instrs[i].IsLdloc() && localConstants != null) {
                int idx = GetLdlocIndex(instrs[i]);
                if (localConstants.ContainsKey(idx)) stack.Push(localConstants[idx]);
                else return -1;
            }
            else if (op == CilCode.Add) { if (stack.Count >= 2) { int b = stack.Pop(); int a = stack.Pop(); stack.Push(a + b); } else return -1; }
            else if (op == CilCode.Sub) { if (stack.Count >= 2) { int b = stack.Pop(); int a = stack.Pop(); stack.Push(a - b); } else return -1; }
            else if (op == CilCode.Mul) { if (stack.Count >= 2) { int b = stack.Pop(); int a = stack.Pop(); stack.Push(a * b); } else return -1; }
            else if (op == CilCode.Div) { if (stack.Count >= 2) { int b = stack.Pop(); int a = stack.Pop(); stack.Push(b == 0 ? 0 : a / b); } else return -1; }
            else if (op == CilCode.Div_Un) { if (stack.Count >= 2) { int b = stack.Pop(); int a = stack.Pop(); stack.Push(b == 0 ? 0 : (int)((uint)a / (uint)b)); } else return -1; }
            else if (op == CilCode.Rem) { if (stack.Count >= 2) { int b = stack.Pop(); int a = stack.Pop(); stack.Push(b == 0 ? 0 : a % b); } else return -1; }
            else if (op == CilCode.Rem_Un) { if (stack.Count >= 2) { int b = stack.Pop(); int a = stack.Pop(); stack.Push(b == 0 ? 0 : (int)((uint)a % (uint)b)); } else return -1; }
            else if (op == CilCode.And) { if (stack.Count >= 2) stack.Push(stack.Pop() & stack.Pop()); else return -1; }
            else if (op == CilCode.Or)  { if (stack.Count >= 2) stack.Push(stack.Pop() | stack.Pop()); else return -1; }
            else if (op == CilCode.Xor) { if (stack.Count >= 2) stack.Push(stack.Pop() ^ stack.Pop()); else return -1; }
            else if (op == CilCode.Shl) { if (stack.Count >= 2) { int b = stack.Pop(); int a = stack.Pop(); stack.Push(a << (b & 31)); } else return -1; }
            else if (op == CilCode.Shr) { if (stack.Count >= 2) { int b = stack.Pop(); int a = stack.Pop(); stack.Push(a >> (b & 31)); } else return -1; }
            else if (op == CilCode.Shr_Un) { if (stack.Count >= 2) { int b = stack.Pop(); int a = stack.Pop(); stack.Push((int)((uint)a >> (b & 31))); } else return -1; }
            else if (op == CilCode.Conv_I4 || op == CilCode.Conv_U4) {  }
            else if (op == CilCode.Conv_U2) { if (stack.Count >= 1) stack.Push((int)(ushort)stack.Pop()); else return -1; }
            else if (op == CilCode.Conv_I1) { if (stack.Count >= 1) stack.Push((int)(sbyte)stack.Pop()); else return -1; }
            else if (op == CilCode.Conv_U1) { if (stack.Count >= 1) stack.Push((int)(byte)stack.Pop()); else return -1; }
            else if (op == CilCode.Conv_I2) { if (stack.Count >= 1) stack.Push((int)(short)stack.Pop()); else return -1; }
            else if (op == CilCode.Neg) { 
                if (stack.Count >= 1) {
                    int v = stack.Pop();
                    if (v == int.MinValue) stack.Push(int.MinValue); 
                    else stack.Push(-v);
                } else return -1; 
            }
            else if (op == CilCode.Not) { if (stack.Count >= 1) stack.Push(~stack.Pop()); else return -1; }
            else if (op == CilCode.Nop) { continue; }
            else {
                
                return -1;
            }
        }
        
        return stack.Count == 1 ? stack.Pop() : -1;
    }

    static void SimplifyControlFlow(CilMethodBody body, HashSet<CilInstruction> jumpTargets)
    {
        var instrs = body.Instructions;
        var localConstants = new Dictionary<Int32, int>();
        bool modified;
        do {
            modified = false;
            localConstants.Clear();

            for (int i = 0; i < instrs.Count; i++) {
                
                if (instrs[i].IsStloc() && i > 0 && instrs[i-1].IsLdcI4()) {
                    int? val = GetLdcI4Value(instrs[i-1]);
                    if (val.HasValue) localConstants[GetStlocIndex(instrs[i])] = val.Value;
                }

                
                if (i >= 2 && instrs[i-2].IsLdloc() && instrs[i-1].IsLdcI4()) {
                    int localIdx = GetLdlocIndex(instrs[i-2]);
                    if (localConstants.ContainsKey(localIdx)) {
                        int v1 = localConstants[localIdx];
                        int v2 = GetLdcI4Value(instrs[i-1]) ?? 0;
                        int? res = null;
                        switch (instrs[i].OpCode.Code) {
                            case CilCode.Add: res = v1 + v2; break;
                            case CilCode.Sub: res = v1 - v2; break;
                            case CilCode.Mul: res = v1 * v2; break;
                            case CilCode.Div: if (v2 != 0) res = v1 / v2; break;
                            case CilCode.Rem: if (v2 != 0) res = v1 % v2; break;
                            case CilCode.And: res = v1 & v2; break;
                            case CilCode.Or:  res = v1 | v2; break;
                            case CilCode.Xor: res = v1 ^ v2; break;
                            case CilCode.Shl: res = v1 << v2; break;
                            case CilCode.Shr: res = v1 >> v2; break;
                        }
                        if (res.HasValue && !jumpTargets.Contains(instrs[i-1]) && !jumpTargets.Contains(instrs[i])) {
                            instrs[i-2].OpCode = CilOpCodes.Nop; instrs[i-2].Operand = null;
                            instrs[i-1].OpCode = CilOpCodes.Nop; instrs[i-1].Operand = null;
                            instrs[i].OpCode = CilOpCodes.Ldc_I4; instrs[i].Operand = res.Value;
                            modified = true;
                        }
                    }
                }
                
                
                if (instrs[i].OpCode.Code == CilCode.Neg && i > 0 && instrs[i-1].IsLdcI4()) {
                    int? val = GetLdcI4Value(instrs[i-1]);
                    if (val.HasValue && !jumpTargets.Contains(instrs[i])) {
                        instrs[i-1].OpCode = CilOpCodes.Nop; instrs[i-1].Operand = null;
                        instrs[i].OpCode = CilOpCodes.Ldc_I4;
                        if (val.Value == int.MinValue) instrs[i].Operand = int.MinValue;
                        else instrs[i].Operand = -val.Value;
                        modified = true;
                    }
                }

                
                if (i >= 2 && instrs[i-2].IsLdcI4() && instrs[i-1].IsLdcI4() && !jumpTargets.Contains(instrs[i-1]) && !jumpTargets.Contains(instrs[i])) {
                    int v1 = GetLdcI4Value(instrs[i-2]) ?? 0;
                    int v2 = GetLdcI4Value(instrs[i-1]) ?? 0;
                    int? res = null;
                    switch (instrs[i].OpCode.Code) {
                        case CilCode.Add: res = v1 + v2; break;
                        case CilCode.Sub: res = v1 - v2; break;
                        case CilCode.Mul: res = v1 * v2; break;
                        case CilCode.Div: if (v2 != 0) res = v1 / v2; break;
                        case CilCode.Rem: if (v2 != 0) res = v1 % v2; break;
                        case CilCode.And: res = v1 & v2; break;
                        case CilCode.Or:  res = v1 | v2; break;
                        case CilCode.Xor: res = v1 ^ v2; break;
                        case CilCode.Shl: res = v1 << v2; break;
                        case CilCode.Shr: res = v1 >> v2; break;
                    }
                    if (res.HasValue) {
                        instrs[i-2].OpCode = CilOpCodes.Nop; instrs[i-2].Operand = null;
                        instrs[i-1].OpCode = CilOpCodes.Nop; instrs[i-1].Operand = null;
                        instrs[i].OpCode = CilOpCodes.Ldc_I4; instrs[i].Operand = res.Value;
                        modified = true;
                    }
                }
                
                
                if (i >= 2 && instrs[i-2].IsLdcI4() && instrs[i-1].IsLdcI4() && !jumpTargets.Contains(instrs[i-1]) && !jumpTargets.Contains(instrs[i])) {
                    int v1 = GetLdcI4Value(instrs[i-2]) ?? 0;
                    int v2 = GetLdcI4Value(instrs[i-1]) ?? 0;
                    bool? branchTaken = null;
                    CilCode op = instrs[i].OpCode.Code;
                    
                    if (op == CilCode.Beq || op == CilCode.Beq_S) branchTaken = v1 == v2;
                    else if (op == CilCode.Bne_Un || op == CilCode.Bne_Un_S) branchTaken = v1 != v2;
                    else if (op == CilCode.Bge || op == CilCode.Bge_S || op == CilCode.Bge_Un || op == CilCode.Bge_Un_S) branchTaken = (uint)v1 >= (uint)v2;
                    else if (op == CilCode.Bgt || op == CilCode.Bgt_S || op == CilCode.Bgt_Un || op == CilCode.Bgt_Un_S) branchTaken = (uint)v1 > (uint)v2;
                    else if (op == CilCode.Ble || op == CilCode.Ble_S || op == CilCode.Ble_Un || op == CilCode.Ble_Un_S) branchTaken = (uint)v1 <= (uint)v2;
                    else if (op == CilCode.Blt || op == CilCode.Blt_S || op == CilCode.Blt_Un || op == CilCode.Blt_Un_S) branchTaken = (uint)v1 < (uint)v2;

                    if (branchTaken.HasValue) {
                        if (branchTaken.Value) {
                            instrs[i-2].OpCode = CilOpCodes.Nop; instrs[i-2].Operand = null;
                            instrs[i-1].OpCode = CilOpCodes.Nop; instrs[i-1].Operand = null;
                            instrs[i].OpCode = CilOpCodes.Br; 
                        } else {
                            instrs[i-2].OpCode = CilOpCodes.Nop; instrs[i-2].Operand = null;
                            instrs[i-1].OpCode = CilOpCodes.Nop; instrs[i-1].Operand = null;
                            instrs[i].OpCode = CilOpCodes.Nop; instrs[i].Operand = null; 
                        }
                        modified = true;
                    }
                }
                
                
                
                if (i >= 2 && instrs[i-2].OpCode.Code == CilCode.Sizeof && instrs[i-1].IsLdcI4()) {
                    int expectedSize = GetLdcI4Value(instrs[i-1]) ?? -1;
                    if (expectedSize != -1) {
                         
                         
                         
                         
                    }
                }
                
                
                
                if (i >= 3 && instrs[i-3].OpCode.Code == CilCode.Call && instrs[i-2].OpCode.Code == CilCode.Call && instrs[i-1].IsLdcI4()) {
                    if (instrs[i-3].Operand is IMethodDescriptor m1 && m1.Name == "get_OSVersion" &&
                        instrs[i-2].Operand is IMethodDescriptor m2 && m2.Name == "get_Platform") {
                        
                        
                        int checkVal = GetLdcI4Value(instrs[i-1]) ?? -1;
                        bool isWin32NT = (checkVal == 2);
                        
                        bool? branchTaken = null;
                        CilCode op = instrs[i].OpCode.Code;
                        
                        
                        
                        
                        if (op == CilCode.Bne_Un || op == CilCode.Bne_Un_S) branchTaken = (2 != checkVal);
                        else if (op == CilCode.Beq || op == CilCode.Beq_S) branchTaken = (2 == checkVal);
                        
                        if (branchTaken.HasValue) {
                            instrs[i-3].OpCode = CilOpCodes.Nop; instrs[i-3].Operand = null;
                            instrs[i-2].OpCode = CilOpCodes.Nop; instrs[i-2].Operand = null;
                            instrs[i-1].OpCode = CilOpCodes.Nop; instrs[i-1].Operand = null;
                            instrs[i].OpCode = branchTaken.Value ? CilOpCodes.Br : CilOpCodes.Nop;
                            if (!branchTaken.Value) instrs[i].Operand = null;
                            modified = true;
                        }
                    }
                }

                
                if (i >= 1 && instrs[i-1].IsLdcI4() && instrs[i].OpCode.Code == CilCode.Switch && !jumpTargets.Contains(instrs[i])) {
                    int val = GetLdcI4Value(instrs[i-1]) ?? -1;
                    var targets = instrs[i].Operand as IList<ICilLabel>;
                    if (targets != null && val >= 0 && val < targets.Count) {
                        instrs[i-1].OpCode = CilOpCodes.Nop; instrs[i-1].Operand = null;
                        instrs[i].OpCode = CilOpCodes.Br;
                        instrs[i].Operand = targets[val];
                        modified = true;
                    } else if (targets != null) {
                        
                        instrs[i-1].OpCode = CilOpCodes.Nop; instrs[i-1].Operand = null;
                        instrs[i].OpCode = CilOpCodes.Nop; instrs[i].Operand = null;
                        modified = true;
                    }
                }
            }
        } while (modified);
    }

    static void InlineProxyCalls(CilMethodBody body, HashSet<CilInstruction> jumpTargets)
     {
         var instrs = body.Instructions;
         for (int i = 0; i < instrs.Count; i++)
         {
             if ((instrs[i].OpCode.Code == CilCode.Call || instrs[i].OpCode.Code == CilCode.Callvirt) && 
                 instrs[i].Operand is MethodDefinition target && target.CilMethodBody != null)
             {
                 var targetInstrs = target.CilMethodBody.Instructions;
                 
                 if (targetInstrs.Count >= 2 && targetInstrs.Count <= 8)
                 {
                     
                     IMethodDescriptor? realTarget = null;
                     bool isSimple = true;
                     int argCount = 0;
                     
                     foreach (var ti in targetInstrs)
                     {
                         if (IsLdarg(ti.OpCode.Code)) argCount++;
                         else if (ti.OpCode.Code == CilCode.Call || ti.OpCode.Code == CilCode.Callvirt)
                         {
                             if (realTarget != null) { isSimple = false; break; }
                             realTarget = ti.Operand as IMethodDescriptor;
                         }
                         else if (ti.OpCode.Code == CilCode.Ret || ti.OpCode.Code == CilCode.Nop) continue;
                         else { isSimple = false; break; }
                     }
                     
                     if (isSimple && realTarget != null && !jumpTargets.Contains(instrs[i]))
                     {
                         
                         bool proxyHasThis = target.Signature?.HasThis == true;
                         bool targetHasThis = realTarget.Signature?.HasThis == true;
                         if (proxyHasThis != targetHasThis) continue;

                         
                         instrs[i].Operand = realTarget;
                     }
                 }
             }
         }
     }

     static void RemoveRedundantControlFlow(CilMethodBody body)
     {
         var instrs = body.Instructions;
         for (int i = 0; i < instrs.Count; i++)
         {
             
             if (instrs[i].OpCode.Code == CilCode.Br || instrs[i].OpCode.Code == CilCode.Br_S)
             {
                 if (instrs[i].Operand is ICilLabel label && label is CilInstructionLabel cilLabel)
                 {
                     if (cilLabel.Instruction == (i < instrs.Count - 1 ? instrs[i+1] : null))
                     {
                         instrs[i].OpCode = CilOpCodes.Nop;
                         instrs[i].Operand = null;
                     }
                 }
             }
         }
     }

     static void DevirtualizeConstantLoader(MethodDefinition method, Assembly assembly)
      {
          if ((string?)method.Name == null || !method.Name!.Contains("VM_ConstantLoader")) return;
         if (method.CilMethodBody == null) return;
         
         var instrs = method.CilMethodBody.Instructions;
         
         
         int switchIndex = -1;
         for (int i = 0; i < instrs.Count; i++) {
             if (instrs[i].OpCode.Code == CilCode.Switch) {
                 switchIndex = i;
                 break;
             }
         }
         
         if (switchIndex == -1) return;
         
         var targets = instrs[switchIndex].Operand as IList<ICilLabel>;
         if (targets == null) return;

         Console.WriteLine($"[+] Attempting dynamic devirtualization of ConstantLoader: {method.Name}");
      }

      static void EmulateVMPControlFlow(MethodDefinition method)
      {
           if (method.CilMethodBody == null) return;
           var body = method.CilMethodBody;
           var instrs = body.Instructions;
           
           
           
           
           
           
           int stateLocalIdx = -1;
           int currentState = 0;
           
           for(int i=0; i<Math.Min(20, instrs.Count); i++) {
               if (instrs[i].IsStloc() && i > 0 && instrs[i-1].IsLdcI4()) {
                   
                   int val = GetLdcI4Value(instrs[i-1]) ?? 0;
                   if (Math.Abs(val) > 1000) {
                       stateLocalIdx = GetStlocIndex(instrs[i]);
                       currentState = val;
                       break;
                   }
               }
           }
           
           if (stateLocalIdx == -1) return;
           
           
           CilInstruction? switchInstr = null;
           int divisor = 0;
           
           foreach(var instr in instrs) {
               if (instr.OpCode.Code == CilCode.Switch) {
                   switchInstr = instr;
                   
                   
                   
                   
                   int idx = instrs.IndexOf(instr);
                   if (idx > 1 && instrs[idx-1].OpCode.Code == CilCode.Rem && instrs[idx-2].IsLdcI4()) {
                       divisor = GetLdcI4Value(instrs[idx-2]) ?? 0;
                   }
                   break;
               }
           }
           
           if (switchInstr == null || divisor == 0) return;
           
           Console.WriteLine($"[+] Found VMP Control Flow Flattening in {method.Name}. State var: {stateLocalIdx}, Divisor: {divisor}");
           
           
           
           
           
           var workList = new Queue<(int instrIdx, int state)>();
           var visited = new HashSet<(int, int)>(); 
           
           
           
           
           
           bool modified = false;
           
           
           
           
           
           
           
           
           
           var stateAt = new Dictionary<int, int>();
           
           
           
           
           
           
           
           
           
           
           
           var switchTargets = switchInstr.Operand as IList<ICilLabel>;
           if (switchTargets == null) return;
           
           
           
           
           
           
           
           
           
           
           
           var loopHead = switchInstr; 
           
           
           
           
           
           
           
           int switchIdx = instrs.IndexOf(switchInstr);
           
           
           int loopHeadIdx = switchIdx;
           while (loopHeadIdx > 0 && !instrs[loopHeadIdx].IsLdloc()) loopHeadIdx--;
           
           
           
           for(int i=0; i<instrs.Count; i++) {
               if (instrs[i].OpCode.Code == CilCode.Br || instrs[i].OpCode.Code == CilCode.Br_S) {
                   if (instrs[i].Operand is ICilLabel label && label is CilInstructionLabel cilLabel && cilLabel.Instruction != null) {
                       int targetIdx = instrs.IndexOf(cilLabel.Instruction);
                       
                       
                       if (targetIdx >= loopHeadIdx && targetIdx <= switchIdx) {
                           
                           
                           
                           
                           
                           
                           
                           
                           int stlocIdx = -1;
                           for(int k=i-1; k>=Math.Max(0, i-50); k--) {
                               if (instrs[k].IsStloc() && GetStlocIndex(instrs[k]) == stateLocalIdx) {
                                   stlocIdx = k;
                                   break;
                               }
                           }
                           
                           if (stlocIdx != -1) {
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                           }
                       }
                   }
               }
           }
           
           
           workList.Enqueue((switchIdx, currentState)); 
           
           
           
           
           
           
           var blockEntryStates = new Dictionary<int, int>(); 
           
           
           
           int entryIdx = -1;
           for(int i=0; i<Math.Min(20, instrs.Count); i++) {
                if (instrs[i].IsStloc() && GetStlocIndex(instrs[i]) == stateLocalIdx) {
                    entryIdx = i + 1;
                    break;
                }
           }
           
           if (entryIdx != -1) {
               var q = new Queue<int>(); 
               q.Enqueue(entryIdx);
               blockEntryStates[entryIdx] = currentState;
               
               int safety = 0;
               while(q.Count > 0 && safety++ < 5000) {
                   int idx = q.Dequeue();
                   if (idx >= instrs.Count || idx < 0) continue;
                   
                   int currentVal = blockEntryStates[idx];
                   
                   
                   Int32 ptr = idx;
                   while(ptr < instrs.Count) {
                       var instr = instrs[ptr];
                       
                       
                       if (instr == switchInstr) {
                           
                           int nextStateIdx = (currentVal % divisor);
                           if (nextStateIdx < 0) nextStateIdx = Math.Abs(nextStateIdx); 
                           
                           if (nextStateIdx < switchTargets.Count) {
                               var targetLabel = switchTargets[nextStateIdx] as CilInstructionLabel;
                               if (targetLabel?.Instruction != null) {
                                   int targetInstrIdx = instrs.IndexOf(targetLabel.Instruction);
                                   if (!blockEntryStates.ContainsKey(targetInstrIdx)) {
                                       blockEntryStates[targetInstrIdx] = currentVal;
                                       q.Enqueue(targetInstrIdx);
                                   }
                               }
                           }
                           break; 
                       }
                       
                       
                       if (instr.IsStloc() && GetStlocIndex(instr) == stateLocalIdx) {
                           
                           
                           
                           int exprStart = ptr;
                           int stackDepth = 0;
                           while (exprStart > 0) {
                               stackDepth += instrs[exprStart-1].OpCode.StackBehaviourPush != CilStackBehaviour.Push0 ? 1 : 0;
                               stackDepth -= (instrs[exprStart-1].OpCode.StackBehaviourPop != CilStackBehaviour.Pop0) ? 1 : 0;
                               if (stackDepth == 1) { exprStart--; break; }
                               exprStart--;
                               if (exprStart < ptr - 50) break;
                           }
                           
                           var tempConsts = new Dictionary<int, int> { { stateLocalIdx, currentVal } };
                           int newVal = SimulateStackForIndex(instrs, exprStart, ptr, tempConsts);
                           
                           if (newVal != -1) {
                               currentVal = newVal;
                               
                           } else {
                               
                               break; 
                           }
                       }
                       
                       
                       if (instr.OpCode.Code == CilCode.Br || instr.OpCode.Code == CilCode.Br_S) {
                            if (instr.Operand is ICilLabel label && label is CilInstructionLabel cilLabel && cilLabel.Instruction != null) {
                                int targetInstrIdx = instrs.IndexOf(cilLabel.Instruction);
                                
                                
                                if (targetInstrIdx >= loopHeadIdx && targetInstrIdx <= switchIdx) {
                                    
                                    
                                    
                                    
                                    
                                    int nextStateIdx = (currentVal % divisor);
                                    if (nextStateIdx < 0) nextStateIdx = Math.Abs(nextStateIdx);
                                    
                                    if (nextStateIdx < switchTargets.Count) {
                                        var realTarget = switchTargets[nextStateIdx];
                                        
                                        instr.Operand = realTarget;
                                        
                                        modified = true;
                                        
                                        
                                        var targetLabel = realTarget as CilInstructionLabel;
                                        if (targetLabel?.Instruction != null) {
                                             int realTargetIdx = instrs.IndexOf(targetLabel.Instruction);
                                             if (!blockEntryStates.ContainsKey(realTargetIdx)) {
                                                blockEntryStates[realTargetIdx] = currentVal;
                                                q.Enqueue(realTargetIdx);
                                             }
                                             
                                        }
                                    }
                                    break; 
                                } else {
                                    
                                    if (!blockEntryStates.ContainsKey(targetInstrIdx)) {
                                        blockEntryStates[targetInstrIdx] = currentVal;
                                        q.Enqueue(targetInstrIdx);
                                    }
                                    break;
                                }
                            }
                       }
                       
                       
                       
                       if (instr.OpCode.Code == CilCode.Brtrue || instr.OpCode.Code == CilCode.Brfalse || 
                           instr.OpCode.Code == CilCode.Beq || instr.OpCode.Code == CilCode.Bne_Un ||
                           instr.OpCode.Code == CilCode.Bge || instr.OpCode.Code == CilCode.Bgt ||
                           instr.OpCode.Code == CilCode.Ble || instr.OpCode.Code == CilCode.Blt) {
                           
                           
                           if (!blockEntryStates.ContainsKey(ptr + 1)) {
                               blockEntryStates[ptr + 1] = currentVal;
                               q.Enqueue(ptr + 1);
                           }
                           
                           
                           if (instr.Operand is ICilLabel label && label is CilInstructionLabel cilLabel && cilLabel.Instruction != null) {
                               int targetInstrIdx = instrs.IndexOf(cilLabel.Instruction);
                               if (!blockEntryStates.ContainsKey(targetInstrIdx)) {
                                   blockEntryStates[targetInstrIdx] = currentVal;
                                   q.Enqueue(targetInstrIdx);
                               }
                           }
                           break; 
                       }
                       
                       if (instr.OpCode.Code == CilCode.Ret) break;
                       
                       ptr++;
                   }
               }
           }
      }

      static void UnflattenControlFlow(CilMethodBody body, HashSet<CilInstruction> jumpTargets)
       {
           if (body.Instructions.Count < 20) return;
           var instrs = body.Instructions;
           
           
           var localConstants = new Dictionary<Int32, int>();

           bool modified;
           do {
               modified = false;
               localConstants.Clear();

               for (int i = 0; i < instrs.Count; i++) {
                   
                   if (jumpTargets.Contains(instrs[i])) {
                       localConstants.Clear();
                   }

                   
                   if (instrs[i].IsStloc() && i > 0 && instrs[i-1].IsLdcI4()) {
                       int? val = GetLdcI4Value(instrs[i-1]);
                       if (val.HasValue) {
                           int localIdx = GetStlocIndex(instrs[i]);
                           localConstants[localIdx] = val.Value;
                       }
                   }

                   
                   if (instrs[i].OpCode.Code == CilCode.Brtrue || instrs[i].OpCode.Code == CilCode.Brfalse || 
                       instrs[i].OpCode.Code == CilCode.Beq || instrs[i].OpCode.Code == CilCode.Bne_Un ||
                       instrs[i].OpCode.Code == CilCode.Bge || instrs[i].OpCode.Code == CilCode.Bgt ||
                       instrs[i].OpCode.Code == CilCode.Ble || instrs[i].OpCode.Code == CilCode.Blt) {
                       
                       localConstants.Clear();
                   }
                   
                   
                   
                   if (instrs[i].OpCode.Code == CilCode.Br || instrs[i].OpCode.Code == CilCode.Br_S) {
                       if (instrs[i].Operand is ICilLabel label && label is CilInstructionLabel cilLabel && cilLabel.Instruction != null) {
                           var target = cilLabel.Instruction;
                           int targetIdx = instrs.IndexOf(target);
                           if (targetIdx != -1 && targetIdx < instrs.Count - 1) {
                               
                               
                               int switchIdx = -1;
                               int divisor = -1;
                               int stateLocalIdx = -1;
                               int stateCalcStartIdx = -1;
                               
                               for (int j = targetIdx; j < Math.Min(targetIdx + 20, instrs.Count); j++) {
                                   if (instrs[j].OpCode.Code == CilCode.Switch) {
                                       switchIdx = j;
                                       break;
                                   }
                                   if (instrs[j].IsLdloc()) {
                                       stateLocalIdx = GetLdlocIndex(instrs[j]);
                                       stateCalcStartIdx = j;
                                   }
                                   if (instrs[j].OpCode.Code == CilCode.Rem && j > 0 && instrs[j-1].IsLdcI4()) {
                                       divisor = GetLdcI4Value(instrs[j-1]) ?? -1;
                                   }
                               }

                               if (switchIdx != -1 && stateLocalIdx != -1) {
                                   Int32 stateVal = 0;
                                   bool hasValue = false;
                                   
                                   
                                   if (localConstants.ContainsKey(stateLocalIdx)) {
                                       stateVal = localConstants[stateLocalIdx];
                                       hasValue = true;
                                   } 
                                   
                                   else {
                                       int prevStlocIdx = -1;
                                       for (int k = i - 1; k >= Math.Max(0, i - 30); k--) {
                                           if (instrs[k].IsStloc() && GetStlocIndex(instrs[k]) == stateLocalIdx) {
                                               prevStlocIdx = k;
                                               break;
                                           }
                                       }
                                       
                                       if (prevStlocIdx != -1) {
                                           
                                           int exprStart = prevStlocIdx;
                                           Int32 stackDepth = 0;
                                           while (exprStart > 0) {
                                               stackDepth += instrs[exprStart-1].OpCode.StackBehaviourPush != CilStackBehaviour.Push0 ? 1 : 0;
                                               stackDepth -= (instrs[exprStart-1].OpCode.StackBehaviourPop != CilStackBehaviour.Pop0) ? 1 : 0; 
                                               if (stackDepth == 1) { exprStart--; break; }
                                               exprStart--;
                                               if (exprStart < prevStlocIdx - 30) break;
                                           }
                                           
                                           int simulated = SimulateStackForIndex(instrs, exprStart, prevStlocIdx, localConstants);
                                           if (simulated != -1) {
                                               stateVal = simulated;
                                               hasValue = true;
                                           }
                                       }
                                   }

                                   if (hasValue) {
                                       localConstants[stateLocalIdx] = stateVal;
                                       int stateValFinal = stateVal;
                                       var switchTargets = instrs[switchIdx].Operand as IList<ICilLabel>;
                                       
                                       if (switchTargets != null) {
                                           int resolvedIndex = divisor != -1 ? (stateValFinal % divisor) : stateValFinal;
                                           
                                           if (resolvedIndex >= 0 && resolvedIndex < switchTargets.Count) {
                                               instrs[i].Operand = switchTargets[resolvedIndex];
                                               modified = true;
                                           } else if (resolvedIndex < 0) {
                                                if (resolvedIndex != int.MinValue) resolvedIndex = Math.Abs(resolvedIndex);
                                                else resolvedIndex = int.MaxValue; 
                                                if (resolvedIndex < switchTargets.Count) {
                                                    instrs[i].Operand = switchTargets[resolvedIndex];
                                                    modified = true;
                                                }
                                            }
                                       }
                                   }
                               }
                           }
                       }
                   }
               }
           } while (modified);
       }

       static int GetStlocIndex(CilInstruction instr) {
           if (instr.OpCode.Code == CilCode.Stloc_0) return 0;
           if (instr.OpCode.Code == CilCode.Stloc_1) return 1;
           if (instr.OpCode.Code == CilCode.Stloc_2) return 2;
           if (instr.OpCode.Code == CilCode.Stloc_3) return 3;
           if (instr.OpCode.Code == CilCode.Stloc_S || instr.OpCode.Code == CilCode.Stloc) {
               if (instr.Operand is CilLocalVariable local) return local.Index;
           }
           return -1;
       }

       static int GetLdlocIndex(CilInstruction instr) {
           if (instr.OpCode.Code == CilCode.Ldloc_0) return 0;
           if (instr.OpCode.Code == CilCode.Ldloc_1) return 1;
           if (instr.OpCode.Code == CilCode.Ldloc_2) return 2;
           if (instr.OpCode.Code == CilCode.Ldloc_3) return 3;
           if (instr.OpCode.Code == CilCode.Ldloc_S || instr.OpCode.Code == CilCode.Ldloc) {
               if (instr.Operand is CilLocalVariable local) return local.Index;
           }
           return -1;
       }

        static void ZeroOutVMData(ModuleDefinition module) {
             int clearedCount = 0;
             long clearedBytes = 0;
             
             foreach (var type in module.GetAllTypes()) {
                 foreach (var field in type.Fields) {
                     
                     
                     try {
                         if (field.FieldRva != null) {
                             if (field.FieldRva is IReadableSegment readable) {
                                 clearedBytes += (long)readable.GetPhysicalSize();
                             }
                             clearedCount++;
                             field.FieldRva = null;
                         }
                         
                         
                         
                         if ((field.Attributes & AsmResolver.PE.DotNet.Metadata.Tables.Rows.FieldAttributes.HasFieldRva) != 0) {
                             field.Attributes &= ~AsmResolver.PE.DotNet.Metadata.Tables.Rows.FieldAttributes.HasFieldRva;
                         }
                     } catch (Exception ex) {
                         
                         
                         try {
                            field.Attributes &= ~AsmResolver.PE.DotNet.Metadata.Tables.Rows.FieldAttributes.HasFieldRva;
                            field.FieldRva = null; 
                         } catch {}
                     }
                 }
             }
             if (clearedCount > 0)
                Console.WriteLine($"[-] Removed {clearedCount} FieldRva segments ({clearedBytes / 1024} KB cleared)");
         }

         static void RemoveDeadCode(CilMethodBody body, HashSet<CilInstruction> jumpTargets) {
             var instrs = body.Instructions;
             for (int i = 0; i < instrs.Count - 1; i++) {
                 var code = instrs[i].OpCode.Code;
                 if (code == CilCode.Br || code == CilCode.Br_S || code == CilCode.Ret || code == CilCode.Throw) {
                     
                     int j = i + 1;
                     while (j < instrs.Count && !jumpTargets.Contains(instrs[j])) {
                         instrs[j].OpCode = CilOpCodes.Nop;
                         instrs[j].Operand = null;
                         j++;
                     }
                 }
             }
         }

    static string? InferTypeNameFromContent(TypeDefinition type, List<string> xorKeys)
    {
        bool hasNet = false, hasFS = false, hasBypass = false, hasCrypto = false, hasRegistry = false, hasProcess = false;
        
        foreach (var m in type.Methods)
        {
            if (m.CilMethodBody == null) continue;
            foreach (var i in m.CilMethodBody.Instructions)
            {
                if (i.Operand is IMethodDescriptor t)
                {
                    string n = t.Name?.ToString() ?? "";
                    string decl = t.DeclaringType?.FullName ?? "";

                    if (decl.Contains("System.Net.Sockets") || decl.Contains("WebClient") || decl.Contains("HttpClient")) hasNet = true;
                    if (decl.Contains("System.IO") || n.Contains("File") || n.Contains("Directory")) hasFS = true;
                    if (n.Contains("Amsi") || n.Contains("Etw") || n.Contains("Patch")) hasBypass = true;
                    if (decl.Contains("Cryptography") || n.Contains("Aes") || n.Contains("Rijndael") || n.Contains("MD5")) hasCrypto = true;
                    if (decl.Contains("Registry") || n.Contains("RegistryKey")) hasRegistry = true;
                    if (decl.Contains("Process") || n.Contains("StartInfo")) hasProcess = true;
                }
            }
        }

        if (hasBypass) return "SecurityBypass_" + type.MetadataToken.ToInt32().ToString("X");
        if (hasNet && hasCrypto) return "NetworkClient_" + type.MetadataToken.ToInt32().ToString("X");
        if (hasNet) return "ConnectionHandler_" + type.MetadataToken.ToInt32().ToString("X");
        if (hasFS && hasRegistry) return "SystemManager_" + type.MetadataToken.ToInt32().ToString("X");
        if (hasFS) return "FileSystemManager_" + type.MetadataToken.ToInt32().ToString("X");
        if (hasRegistry) return "RegistryManager_" + type.MetadataToken.ToInt32().ToString("X");
        if (hasProcess) return "ProcessManager_" + type.MetadataToken.ToInt32().ToString("X");
        if (hasCrypto) return "CryptoHelper_" + type.MetadataToken.ToInt32().ToString("X");

        return null;
    }

    static int? GetLdcI4Value(CilInstruction instr)
    {
        if (instr.OpCode.Code >= CilCode.Ldc_I4_0 && instr.OpCode.Code <= CilCode.Ldc_I4_8) return instr.OpCode.Code - CilCode.Ldc_I4_0;
        if (instr.OpCode.Code == CilCode.Ldc_I4_M1) return -1;
        if (instr.Operand is sbyte s) return s;
        if (instr.Operand is int i) return i;
        return null;
    }

    static void RemoveEmptyNestedTypes(TypeDefinition type) { } 

    static bool IsTypeEmpty(TypeDefinition type)
    {
        if (type.Methods.Count > 0) return false;
        if (type.Fields.Count > 0) return false;
        if (type.Properties.Count > 0) return false;
        if (type.Events.Count > 0) return false;
        if (type.NestedTypes.Count > 0) return false;
        
        if (type.Interfaces.Count > 0) return false;
        if (type.GenericParameters.Count > 0) return false;
        if (type.ClassLayout != null) return false; 
         string typeName = type.Name?.ToString() ?? "";
         if (typeName.Contains("<PrivateImplementationDetails>") || typeName.StartsWith("__StaticArrayInit")) return false;
         return true;
     }

    static IEnumerable<Type> GetAllNestedTypes(Type type)
    {
        yield return type;
        foreach (var nt in type.GetNestedTypes(BindingFlags.Public | BindingFlags.NonPublic))
            foreach (var t in GetAllNestedTypes(nt)) yield return t;
    }

    static Dictionary<int, IMethodDescriptor> ExtractProxyTableStatic(IFieldDescriptor arrayField)
    {
        var result = new Dictionary<int, IMethodDescriptor>();
        try
        {
            var type = arrayField.DeclaringType?.Resolve();
            if (type == null) return result;

            var cctor = type.GetStaticConstructor();
            if (cctor == null || cctor.CilMethodBody == null) return result;

            var instrs = cctor.CilMethodBody.Instructions;
            
            for (int i = 0; i < instrs.Count - 4; i++)
            {
                if (instrs[i].IsLdcI4())
                {
                    int? index = GetLdcI4Value(instrs[i]);
                    if (!index.HasValue) continue;

                    
                    if (instrs[i + 1].OpCode.Code == CilCode.Ldtoken && instrs[i + 1].Operand is IMethodDescriptor targetMethod &&
                        (instrs[i + 2].OpCode.Code == CilCode.Call || instrs[i + 2].OpCode.Code == CilCode.Callvirt) &&
                        instrs[i + 3].OpCode.Code == CilCode.Stelem_Ref)
                    {
                        result[index.Value] = targetMethod;
                    }
                    
                    else if (instrs[i + 1].OpCode.Code == CilCode.Ldtoken && instrs[i + 1].Operand is IMethodDescriptor targetMethod2 &&
                        (instrs[i + 2].OpCode.Code == CilCode.Call || instrs[i + 2].OpCode.Code == CilCode.Callvirt) &&
                        instrs[i + 3].OpCode.Code == CilCode.Castclass &&
                        instrs[i + 4].OpCode.Code == CilCode.Stelem_Ref)
                    {
                        result[index.Value] = targetMethod2;
                    }
                    
                    else if (instrs[i + 1].OpCode.Code == CilCode.Ldnull && 
                        instrs[i + 2].OpCode.Code == CilCode.Ldftn && instrs[i + 2].Operand is IMethodDescriptor targetMethod3 &&
                        instrs[i + 3].OpCode.Code == CilCode.Newobj &&
                        instrs[i + 4].OpCode.Code == CilCode.Stelem_Ref)
                    {
                         result[index.Value] = targetMethod3;
                    }
                    
                    else if (instrs[i + 1].OpCode.Code == CilCode.Ldftn && instrs[i + 1].Operand is IMethodDescriptor targetMethod4 &&
                        instrs[i + 2].OpCode.Code == CilCode.Newobj &&
                        instrs[i + 3].OpCode.Code == CilCode.Stelem_Ref)
                    {
                         result[index.Value] = targetMethod4;
                    }
                }
            }
        }
        catch { }
        return result;
    }
}

class TraceAnalyzer
{
    public TraceAnalyzer(string path) { }
    public string Analyze() => "Trace analysis not yet implemented.";
}