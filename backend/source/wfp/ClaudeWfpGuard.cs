// Native Windows Filtering Platform helper, x64 only. No third-party libraries.
// Does nothing to the machine until the explicit `install` or `remove` command.
// Data types/GUIDs checked against microsoft/win32metadata fwpmu.h,
// shared/fwpmtypes.h and shared/fwptypes.h, retrieved 2026-10-23.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Web.Script.Serialization;

internal static class ClaudeWfpGuard {
    const uint Persistent = 1, Block = 0x1001, MatchEqual = 0, MatchNotEqual = 10;
    const uint TypeUint8 = 1, TypeUint16 = 2, TypeUint32 = 3, TypeByteBlob = 12, TypeSid = 13;
    const uint AlreadyExists = 0x80320009, FilterNotFound = 0x80320003, ProviderNotFound = 0x80320005, SubLayerNotFound = 0x80320007;
    const ushort GatewayPort = 17894;
    static readonly Guid ProviderKey = new Guid("072c56c8-439b-434c-a899-bb4cc945fb3a");
    static readonly Guid SubLayerKey = new Guid("6f9118a2-a061-4a24-8e9a-19df01e157c8");
    static readonly Guid ProbeProviderKey = new Guid("d57caaae-6f57-43f8-b831-3e72bccaf37b");
    static readonly Guid ProbeSubLayerKey = new Guid("f91c2df7-108b-41f3-8269-58ae31221054");
    static readonly Guid ConnectV4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    static readonly Guid ConnectV6 = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    static readonly Guid AppId = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
    static readonly Guid PackageId = new Guid("71bc78fa-f17c-4997-a602-6abb261f351c");
    static readonly Guid RemoteAddress = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    static readonly Guid RemotePort = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");
    static readonly Guid Protocol = new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
    const string Family = "Claude_pzs8sxrjxfjjc";
    const string Label = "Claude Network Guard";

    [StructLayout(LayoutKind.Sequential)] struct DisplayData { public IntPtr name, description; }
    [StructLayout(LayoutKind.Sequential)] struct ByteBlob { public uint size; public IntPtr data; }
    [StructLayout(LayoutKind.Explicit, Size=8)] struct ValueUnion {
        [FieldOffset(0)] public byte u8;
        [FieldOffset(0)] public ushort u16;
        [FieldOffset(0)] public uint u32;
        [FieldOffset(0)] public IntPtr ptr;
    }
    [StructLayout(LayoutKind.Sequential)] struct FwpValue { public uint type; public ValueUnion value; }
    [StructLayout(LayoutKind.Sequential)] struct Condition { public Guid fieldKey; public uint matchType; public FwpValue conditionValue; }
    [StructLayout(LayoutKind.Sequential)] struct Action { public uint type; public Guid filterType; }
    [StructLayout(LayoutKind.Explicit, Size=16)] struct ContextUnion {
        [FieldOffset(0)] public ulong rawContext;
        [FieldOffset(0)] public Guid providerContextKey;
    }
    [StructLayout(LayoutKind.Sequential)] struct Filter {
        public Guid filterKey;
        public DisplayData displayData;
        public uint flags;
        public IntPtr providerKey;
        public ByteBlob providerData;
        public Guid layerKey, subLayerKey;
        public FwpValue weight;
        public uint numFilterConditions;
        public IntPtr filterCondition;
        public Action action;
        public ContextUnion context;
        public IntPtr reserved;
        public ulong filterId;
        public FwpValue effectiveWeight;
    }
    [StructLayout(LayoutKind.Sequential)] struct Provider {
        public Guid providerKey; public DisplayData displayData; public uint flags;
        public ByteBlob providerData; public IntPtr serviceName;
    }
    [StructLayout(LayoutKind.Sequential)] struct SubLayer {
        public Guid subLayerKey; public DisplayData displayData; public uint flags;
        public IntPtr providerKey; public ByteBlob providerData; public ushort weight;
    }

    static class Native {
        [DllImport("fwpuclnt.dll", ExactSpelling=true, CharSet=CharSet.Unicode)] internal static extern uint FwpmEngineOpen0(string serverName, uint authnService, IntPtr authIdentity, IntPtr session, out IntPtr engine);
        [DllImport("fwpuclnt.dll", ExactSpelling=true)] internal static extern uint FwpmEngineClose0(IntPtr engine);
        [DllImport("fwpuclnt.dll", ExactSpelling=true)] internal static extern uint FwpmTransactionBegin0(IntPtr engine, uint flags);
        [DllImport("fwpuclnt.dll", ExactSpelling=true)] internal static extern uint FwpmTransactionCommit0(IntPtr engine);
        [DllImport("fwpuclnt.dll", ExactSpelling=true)] internal static extern uint FwpmTransactionAbort0(IntPtr engine);
        [DllImport("fwpuclnt.dll", ExactSpelling=true)] internal static extern uint FwpmProviderAdd0(IntPtr engine, ref Provider provider, IntPtr sd);
        [DllImport("fwpuclnt.dll", ExactSpelling=true)] internal static extern uint FwpmProviderGetByKey0(IntPtr engine, ref Guid key, out IntPtr provider);
        [DllImport("fwpuclnt.dll", ExactSpelling=true)] internal static extern uint FwpmProviderDeleteByKey0(IntPtr engine, ref Guid key);
        [DllImport("fwpuclnt.dll", ExactSpelling=true)] internal static extern uint FwpmSubLayerAdd0(IntPtr engine, ref SubLayer subLayer, IntPtr sd);
        [DllImport("fwpuclnt.dll", ExactSpelling=true)] internal static extern uint FwpmSubLayerGetByKey0(IntPtr engine, ref Guid key, out IntPtr subLayer);
        [DllImport("fwpuclnt.dll", ExactSpelling=true)] internal static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine, ref Guid key);
        [DllImport("fwpuclnt.dll", ExactSpelling=true)] internal static extern uint FwpmFilterAdd0(IntPtr engine, ref Filter filter, IntPtr sd, out ulong id);
        [DllImport("fwpuclnt.dll", ExactSpelling=true)] internal static extern uint FwpmFilterDeleteByKey0(IntPtr engine, ref Guid key);
        [DllImport("fwpuclnt.dll", ExactSpelling=true)] internal static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine, IntPtr template, out IntPtr enumHandle);
        [DllImport("fwpuclnt.dll", ExactSpelling=true)] internal static extern uint FwpmFilterEnum0(IntPtr engine, IntPtr enumHandle, uint requested, out IntPtr entries, out uint returned);
        [DllImport("fwpuclnt.dll", ExactSpelling=true)] internal static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine, IntPtr enumHandle);
        [DllImport("fwpuclnt.dll", ExactSpelling=true)] internal static extern uint FwpmGetAppIdFromFileName0([MarshalAs(UnmanagedType.LPWStr)] string fileName, out IntPtr appId);
        [DllImport("fwpuclnt.dll", ExactSpelling=true)] internal static extern void FwpmFreeMemory0(ref IntPtr memory);
        [DllImport("userenv.dll", ExactSpelling=true, CharSet=CharSet.Unicode)] internal static extern int DeriveAppContainerSidFromAppContainerName(string appContainerName, out IntPtr sid);
        [DllImport("advapi32.dll", ExactSpelling=true)] internal static extern IntPtr FreeSid(IntPtr sid);
    }
    sealed class Arena : IDisposable {
        readonly List<IntPtr> allocations = new List<IntPtr>();
        public IntPtr Struct<T>(T value) {
            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(T)));
            allocations.Add(ptr); Marshal.StructureToPtr(value, ptr, false); return ptr;
        }
        public IntPtr Text(string value) { IntPtr ptr=Marshal.StringToHGlobalUni(value); allocations.Add(ptr); return ptr; }
        public IntPtr Conditions(Condition[] items) {
            int size=Marshal.SizeOf(typeof(Condition)); IntPtr ptr=Marshal.AllocHGlobal(size*items.Length); allocations.Add(ptr);
            for(int i=0;i<items.Length;i++) Marshal.StructureToPtr(items[i], IntPtr.Add(ptr,size*i),false);
            return ptr;
        }
        public void Dispose() { foreach(IntPtr ptr in allocations) Marshal.FreeHGlobal(ptr); allocations.Clear(); }
    }
    sealed class Engine : IDisposable {
        public IntPtr Handle; public bool Transaction;
        public Engine() { Check(Native.FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out Handle),"FwpmEngineOpen0"); }
        public void Begin() { Check(Native.FwpmTransactionBegin0(Handle,0),"FwpmTransactionBegin0"); Transaction=true; }
        public void Commit() { Check(Native.FwpmTransactionCommit0(Handle),"FwpmTransactionCommit0"); Transaction=false; }
        public void Dispose() {
            if(Handle!=IntPtr.Zero) {
                if(Transaction) { uint rc=Native.FwpmTransactionAbort0(Handle); if(rc!=0) Console.Error.WriteLine("Transaction abort returned 0x"+rc.ToString("X8")); }
                uint close=Native.FwpmEngineClose0(Handle); Handle=IntPtr.Zero;
                if(close!=0) Console.Error.WriteLine("Engine close returned 0x"+close.ToString("X8"));
            }
        }
    }
    sealed class Scope : IDisposable {
        public string Key,Name; public Guid Field; public uint Type; public IntPtr Pointer;
        public bool IsSid;
        public Condition Identity() { return PointerCondition(Field,MatchEqual,Type,Pointer); }
        public void Dispose() { if(Pointer==IntPtr.Zero)return; if(IsSid)Native.FreeSid(Pointer);else Native.FwpmFreeMemory0(ref Pointer); Pointer=IntPtr.Zero; }
    }
    static void Check(uint rc,string operation) { if(rc!=0)throw new InvalidOperationException(operation+" failed: 0x"+rc.ToString("X8")+" ("+new Win32Exception(unchecked((int)rc)).Message+")"); }
    static void AssertLayout() {
        if(IntPtr.Size!=8)throw new PlatformNotSupportedException("This helper must run as x64.");
        Size(typeof(ByteBlob),16); Size(typeof(FwpValue),16); Size(typeof(Condition),40); Size(typeof(Action),20); Size(typeof(Filter),200); Size(typeof(Provider),64); Size(typeof(SubLayer),72);
        Offset(typeof(Filter),"providerKey",40); Offset(typeof(Filter),"filterCondition",120); Offset(typeof(Filter),"action",128); Offset(typeof(Filter),"context",152); Offset(typeof(Filter),"filterId",176); Offset(typeof(Filter),"effectiveWeight",184);
    }
    static void Size(Type type,int expected) { if(Marshal.SizeOf(type)!=expected)throw new InvalidOperationException(type.Name+" ABI size mismatch."); }
    static void Offset(Type type,string field,int expected) { if(Marshal.OffsetOf(type,field).ToInt32()!=expected)throw new InvalidOperationException(type.Name+"."+field+" ABI offset mismatch."); }
    static Condition PointerCondition(Guid field,uint match,uint type,IntPtr value) { Condition c=new Condition();c.fieldKey=field;c.matchType=match;c.conditionValue.type=type;c.conditionValue.value.ptr=value;return c; }
    static Condition NumberCondition(Guid field,uint match,uint type,uint value) { Condition c=new Condition();c.fieldKey=field;c.matchType=match;c.conditionValue.type=type;c.conditionValue.value.u32=value;return c; }
    static Scope AppScope(string path) {
        string full=Path.GetFullPath(path);if(!File.Exists(full))throw new FileNotFoundException("Scoped executable not found",full);
        if(!String.Equals(Path.GetExtension(full),".exe",StringComparison.OrdinalIgnoreCase))throw new ArgumentException("App scope must be an explicit .exe path.");
        Scope s=new Scope();s.Key="app:"+full.ToLowerInvariant();s.Name=full;s.Field=AppId;s.Type=TypeByteBlob;
        Check(Native.FwpmGetAppIdFromFileName0(full,out s.Pointer),"FwpmGetAppIdFromFileName0");return s;
    }
    static Scope PackageScope(string family) {
        if(family!=Family)throw new ArgumentException("Production package scope must be "+Family);
        Scope s=new Scope();s.Key="package:"+family;s.Name=family;s.Field=PackageId;s.Type=TypeSid;s.IsSid=true;
        int rc=Native.DeriveAppContainerSidFromAppContainerName(family,out s.Pointer);
        if(rc<0)Marshal.ThrowExceptionForHR(rc);return s;
    }
    static Guid StableKey(Guid provider,string scope,string suffix) {
        using(SHA256 sha=SHA256.Create()) { byte[] hash=sha.ComputeHash(Encoding.UTF8.GetBytes(provider.ToString("D")+"|"+scope+"|"+suffix));byte[] key=new byte[16];Array.Copy(hash,key,16);return new Guid(key); }
    }
    static void EnsureProvider(Engine engine,Arena arena,Guid providerKey,Guid subLayerKey,string service,bool probe) {
        string name=probe?Label+" Probe":Label;IntPtr existing=IntPtr.Zero;
        uint result=Native.FwpmProviderGetByKey0(engine.Handle,ref providerKey,out existing);
        if(result==0) {
            try { Provider p=(Provider)Marshal.PtrToStructure(existing,typeof(Provider));
                if(Marshal.PtrToStringUni(p.displayData.name)!=name||Marshal.PtrToStringUni(p.serviceName)!=service||(p.flags&0x10)!=0)throw new InvalidOperationException("Existing provider ownership, service association, or activation state differs. Remove the existing owned policy before reinstalling.");
            } finally {Native.FwpmFreeMemory0(ref existing);}
        } else {
            if(result!=ProviderNotFound)Check(result,"FwpmProviderGetByKey0");
            Provider p=new Provider();p.providerKey=providerKey;p.flags=Persistent;p.displayData.name=arena.Text(name);p.displayData.description=arena.Text("Scoped outbound blocks; only TCP 127.0.0.1:17894 is outside these blocks. No allow overrides.");p.serviceName=arena.Text(service);
            Check(Native.FwpmProviderAdd0(engine.Handle,ref p,IntPtr.Zero),"FwpmProviderAdd0");
        }
        existing=IntPtr.Zero;result=Native.FwpmSubLayerGetByKey0(engine.Handle,ref subLayerKey,out existing);
        if(result==0) {
            try {SubLayer s=(SubLayer)Marshal.PtrToStructure(existing,typeof(SubLayer));
                if(Marshal.PtrToStringUni(s.displayData.name)!=name||s.providerKey==IntPtr.Zero||(Guid)Marshal.PtrToStructure(s.providerKey,typeof(Guid))!=providerKey)throw new InvalidOperationException("Existing sublayer ownership differs.");
            } finally {Native.FwpmFreeMemory0(ref existing);}
        } else {
            if(result!=SubLayerNotFound)Check(result,"FwpmSubLayerGetByKey0");
            SubLayer s=new SubLayer();s.subLayerKey=subLayerKey;s.flags=Persistent;s.providerKey=arena.Struct(providerKey);s.displayData.name=arena.Text(name);s.displayData.description=arena.Text("App/package identity-scoped fail-closed gateway restriction.");s.weight=0xF000;
            Check(Native.FwpmSubLayerAdd0(engine.Handle,ref s,IntPtr.Zero),"FwpmSubLayerAdd0");
        }
    }
    static List<Filter> OwnedFilters(Engine engine,Guid providerKey) {
        List<Filter> owned=new List<Filter>();IntPtr enumerator=IntPtr.Zero;
        Check(Native.FwpmFilterCreateEnumHandle0(engine.Handle,IntPtr.Zero,out enumerator),"FwpmFilterCreateEnumHandle0");
        try { while(true) {IntPtr entries=IntPtr.Zero;uint count=0;
                try { Check(Native.FwpmFilterEnum0(engine.Handle,enumerator,256,out entries,out count),"FwpmFilterEnum0");
                    for(uint i=0;i<count;i++) {IntPtr ptr=Marshal.ReadIntPtr(entries,checked((int)i*IntPtr.Size));Filter f=(Filter)Marshal.PtrToStructure(ptr,typeof(Filter));
                        if(f.providerKey!=IntPtr.Zero&&(Guid)Marshal.PtrToStructure(f.providerKey,typeof(Guid))==providerKey) {
                            // Copy only scalar/managed-owned fields: native memory is released below.
                            Filter copy=new Filter();copy.filterKey=f.filterKey;copy.filterId=f.filterId;copy.flags=f.flags;copy.layerKey=f.layerKey;copy.subLayerKey=f.subLayerKey;copy.action=f.action;copy.numFilterConditions=f.numFilterConditions;owned.Add(copy);
                        }
                    }
                } finally {if(entries!=IntPtr.Zero)Native.FwpmFreeMemory0(ref entries);}
                if(count<256)break;
            }
        } finally { if(enumerator!=IntPtr.Zero)Check(Native.FwpmFilterDestroyEnumHandle0(engine.Handle,enumerator),"FwpmFilterDestroyEnumHandle0"); }
        return owned;
    }
    static int DeleteOwned(Engine engine,Guid providerKey) { List<Filter> owned=OwnedFilters(engine,providerKey);foreach(Filter f in owned){Guid key=f.filterKey;Check(Native.FwpmFilterDeleteByKey0(engine.Handle,ref key),"FwpmFilterDeleteByKey0");}return owned.Count; }
    static void AddFilter(Engine engine,Arena arena,Guid providerKey,Guid subLayerKey,Scope scope,string suffix,Guid layer,Condition[] conditions) {
        if(conditions.Length<1||conditions[0].fieldKey!=scope.Field||conditions[0].matchType!=MatchEqual)throw new InvalidOperationException("Missing target identity; refusing unscoped filter.");
        Filter filter=new Filter();filter.filterKey=StableKey(providerKey,scope.Key,suffix);filter.flags=Persistent;filter.providerKey=arena.Struct(providerKey);filter.layerKey=layer;filter.subLayerKey=subLayerKey;
        filter.displayData.name=arena.Text(Label+" | "+scope.Name+" | "+suffix);filter.displayData.description=arena.Text("Only the specified app or package identity is matched. Deny rule; no permit action.");
        filter.weight.type=TypeUint8;filter.weight.value.u8=15;filter.numFilterConditions=(uint)conditions.Length;filter.filterCondition=arena.Conditions(conditions);filter.action.type=Block;
        ulong id;Check(Native.FwpmFilterAdd0(engine.Handle,ref filter,IntPtr.Zero,out id),"FwpmFilterAdd0("+suffix+")");
    }
    static void AddScope(Engine engine,Arena arena,Guid provider,Guid subLayer,Scope scope) {
        Condition identity=scope.Identity();
        // Each separate block is identity AND forbidden property. Their union leaves
        // only exact IPv4 loopback TCP gateway connections outside this policy.
        AddFilter(engine,arena,provider,subLayer,scope,"v4-address-not-gateway",ConnectV4,new Condition[]{identity,NumberCondition(RemoteAddress,MatchNotEqual,TypeUint32,0x7F000001)});
        AddFilter(engine,arena,provider,subLayer,scope,"v4-port-not-gateway",ConnectV4,new Condition[]{identity,NumberCondition(RemotePort,MatchNotEqual,TypeUint16,GatewayPort)});
        AddFilter(engine,arena,provider,subLayer,scope,"v4-protocol-not-tcp",ConnectV4,new Condition[]{identity,NumberCondition(Protocol,MatchNotEqual,TypeUint8,6)});
        AddFilter(engine,arena,provider,subLayer,scope,"v6-block-all",ConnectV6,new Condition[]{identity});
    }
    static object Describe(Engine engine,Guid provider,Guid subLayer,bool probe) {
        IntPtr ptr=IntPtr.Zero;uint rc=Native.FwpmProviderGetByKey0(engine.Handle,ref provider,out ptr);bool present=rc==0;uint flags=0;string service=null;
        if(present) {try {Provider p=(Provider)Marshal.PtrToStructure(ptr,typeof(Provider));flags=p.flags;service=Marshal.PtrToStringUni(p.serviceName);}finally{Native.FwpmFreeMemory0(ref ptr);}}
        else if(rc!=ProviderNotFound)Check(rc,"FwpmProviderGetByKey0");
        List<object> rows=new List<object>();int disabled=0;
        foreach(Filter f in OwnedFilters(engine,provider)) {bool off=(f.flags&0x20)!=0;if(off)disabled++;rows.Add(new{key=f.filterKey,id=f.filterId,persistent=(f.flags&1)!=0,disabled=off,layer=f.layerKey==ConnectV4?"ALE_AUTH_CONNECT_V4":f.layerKey==ConnectV6?"ALE_AUTH_CONNECT_V6":f.layerKey.ToString(),identityConditions=f.numFilterConditions,block=f.action.type==Block,sublayer=f.subLayerKey});}
        return new {probe=probe,providerKey=provider,sublayerKey=subLayer,providerPresent=present,providerPersistent=(flags&1)!=0,providerDisabled=(flags&0x10)!=0,serviceName=service,gateway="127.0.0.1:17894/TCP",filterCount=rows.Count,disabledFilterCount=disabled,filters=rows};
    }
    static int Main(string[] args) {
        List<Scope> scopes=new List<Scope>();
        try {
            AssertLayout();if(args.Length==0){Usage();return 2;}
            string command=args[0].ToLowerInvariant(),family=null,probePath=null,service="BFE";List<string> paths=new List<string>();
            for(int i=1;i<args.Length;i++) {string option=args[i];if(i+1>=args.Length)throw new ArgumentException("Missing value for "+option);string value=args[++i];
                if(option=="--app")paths.Add(value);else if(option=="--family")family=value;else if(option=="--probe")probePath=value;else if(option=="--service")service=value;else throw new ArgumentException("Unknown option "+option);
            }
            bool probe=probePath!=null;if(probe&&(paths.Count!=0||family!=null))throw new ArgumentException("Probe is a separate policy; do not mix --probe with production scope.");
            Guid provider=probe?ProbeProviderKey:ProviderKey,subLayer=probe?ProbeSubLayerKey:SubLayerKey;
            if(command=="plan"||command=="install") {
                if(probe)scopes.Add(AppScope(probePath));else {foreach(string path in paths)scopes.Add(AppScope(path));if(family!=null)scopes.Add(PackageScope(family));}
                if(scopes.Count==0)throw new ArgumentException("Explicit --app paths and/or exact --family are required.");
                HashSet<string> unique=new HashSet<string>(StringComparer.OrdinalIgnoreCase);foreach(Scope scope in scopes)if(!unique.Add(scope.Key))throw new ArgumentException("Duplicate scope: "+scope.Name);
                if(command=="plan") {List<object> rows=new List<object>();foreach(Scope s in scopes)rows.Add(new{identity=s.Name,type=s.IsSid?"packageSid":"executableAppId",sid=s.IsSid?new SecurityIdentifier(s.Pointer).Value:null});Print(new{command="plan",mutated=false,providerKey=provider,sublayerKey=subLayer,serviceName=service,gateway="127.0.0.1:17894/TCP",expectedFilterCount=scopes.Count*4,scopes=rows,abi="x64 verified"});return 0;}
                RequireAdmin();using(Engine engine=new Engine())using(Arena arena=new Arena()) {engine.Begin();EnsureProvider(engine,arena,provider,subLayer,service,probe);DeleteOwned(engine,provider);foreach(Scope scope in scopes)AddScope(engine,arena,provider,subLayer,scope);engine.Commit();Print(Describe(engine,provider,subLayer,probe));}return 0;
            }
            if(command=="list") {using(Engine engine=new Engine())Print(Describe(engine,provider,subLayer,probe));return 0;}
            if(command=="remove") {
                RequireAdmin();using(Engine engine=new Engine()) {engine.Begin();int removed=DeleteOwned(engine,provider);uint rc=Native.FwpmSubLayerDeleteByKey0(engine.Handle,ref subLayer);if(rc!=SubLayerNotFound)Check(rc,"FwpmSubLayerDeleteByKey0");rc=Native.FwpmProviderDeleteByKey0(engine.Handle,ref provider);if(rc!=ProviderNotFound)Check(rc,"FwpmProviderDeleteByKey0");engine.Commit();Print(new{command="remove",probe=probe,removedFilterCount=removed,providerKey=provider});}return 0;
            }
            throw new ArgumentException("Unknown command: "+command);
        } catch(Exception ex) {Console.Error.WriteLine("ClaudeWfpGuard: "+ex.Message);return 1;}
        finally {foreach(Scope scope in scopes)scope.Dispose();}
    }
    static void RequireAdmin() {WindowsPrincipal principal=new WindowsPrincipal(WindowsIdentity.GetCurrent());if(!principal.IsInRole(WindowsBuiltInRole.Administrator))throw new UnauthorizedAccessException("install/remove require elevation; no changes were made.");}
    static void Print(object value) {Console.WriteLine(new JavaScriptSerializer().Serialize(value));}
    static void Usage() {Console.WriteLine("ClaudeWfpGuard plan|install --app <exact.exe> [--app ...] [--family Claude_pzs8sxrjxfjjc] [--service BFE]\nClaudeWfpGuard plan|install --probe <exact-probe.exe> [--service BFE]\nClaudeWfpGuard list|remove [--probe <exact-probe.exe>]\nNo runtime mutation occurs for plan/list. install/remove require administrator privileges. Probe policy is independent of production policy.");}
}
