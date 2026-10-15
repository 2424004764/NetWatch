using System;
using System.Runtime.InteropServices;

namespace NetWatch.Core.Wfp;

/// <summary>WFP（Windows 筛选平台）本机 API 的互操作定义。仅声明“添加/删除出站屏蔽过滤器”所需的最小集合。</summary>
internal static class WfpNative
{
    // FWP_ACTION_TYPE
    internal const uint FWP_ACTION_BLOCK = 0x1001; // 0x1 | FWP_ACTION_FLAG_TERMINATING
    internal const uint FWP_ACTION_CALLOUT_TERMINATING = 0x5003;
    internal const uint FWPM_SESSION_FLAG_DYNAMIC = 1;
    internal const uint FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED = 0x10;
    internal const uint FWPM_FILTER_FLAG_DISABLED = 0x20;
    // FWP_DATA_TYPE（本实现用到的）
    internal const uint FWP_EMPTY = 0;
    internal const uint FWP_UINT64 = 4;
    internal const uint FWP_BYTE_BLOB_TYPE = 12;
    internal const uint FWP_V4_ADDR_MASK = 0x100;
    internal const uint FWP_V6_ADDR_MASK = 0x101;

    internal const uint RPC_C_AUTHN_WINNT = 10;
    internal const uint FWP_E_ALREADY_EXISTS = 0x80320009;
    internal const uint FWP_MATCH_EQUAL = 0;

    internal static readonly Guid LayerAleAuthConnectV4 = new("C38D57D1-05A7-4C33-904F-7FBCEEE60E82");
    internal static readonly Guid LayerAleAuthConnectV6 = new("4A72393B-319F-44BC-84C3-BA54DCB3B6B4");
    internal static readonly Guid ConditionAleAppId = new("D78E1E87-8644-4EA5-9437-D809ECEFC971");
    internal static readonly Guid ConditionIpRemoteAddress = new("B235AE9A-1D64-49B8-A44C-5FF3D9095045");
    internal static readonly Guid LayerAleFlowEstablishedV4 = new("AF80470A-5596-4C13-9992-539E6FE57967");
    internal static readonly Guid LayerAleFlowEstablishedV6 = new("7021D2B3-DFA4-406E-AFEB-6AFAF7E70EFD");
    internal static readonly Guid LayerOutboundTransportV4 = new("09E61AEA-D214-46E2-9B21-B26B0B2F28C8");
    internal static readonly Guid LayerOutboundTransportV6 = new("E1735BDE-013F-4655-B351-A49E15762DF0");

    /// <summary>本机动态 WFP session；BFE 在 engine handle 关闭时删除其中的临时对象。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_SESSION0
    {
        public Guid SessionKey;
        public FWPM_DISPLAY_DATA0 DisplayData;
        public uint Flags;
        public uint TxnWaitTimeoutInMSec;
        public uint ProcessId;
        public IntPtr Sid;
        public IntPtr Username;
        [MarshalAs(UnmanagedType.Bool)] public bool KernelMode;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_PROVIDER0
    {
        public Guid ProviderKey;
        public FWPM_DISPLAY_DATA0 DisplayData;
        public uint Flags;
        public FWP_BYTE_BLOB ProviderData;
        public IntPtr ServiceName;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_CALLOUT0
    {
        public Guid CalloutKey;
        public FWPM_DISPLAY_DATA0 DisplayData;
        public uint Flags;
        public IntPtr ProviderKey;
        public FWP_BYTE_BLOB ProviderData;
        public Guid ApplicableLayer;
        public uint CalloutId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_DISPLAY_DATA0
    {
        public IntPtr Name;        // wchar_t*
        public IntPtr Description; // wchar_t*
    }

    /// <summary>FWP_BYTE_BLOB / FWPM_APP_ID0（同构）。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_BYTE_BLOB
    {
        public uint Size;
        public IntPtr Data;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct V4AddrMask
    {
        public uint Addr;
        public uint Mask;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct V6AddrAndMask
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Addr;
        public byte PrefixLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_VALUE0
    {
        public uint Type;
        public FWP_VALUE0Union Value;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct FWP_VALUE0Union
    {
        [FieldOffset(0)] public ulong Uint64;
        [FieldOffset(0)] public IntPtr Pointer;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_CONDITION_VALUE0
    {
        public uint Type;
        public FWP_VALUE0Union Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_FILTER_CONDITION0
    {
        public Guid FieldKey;
        public uint MatchType;
        public FWP_CONDITION_VALUE0 ConditionValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_ACTION0
    {
        public uint Type;
        public Guid Union; // union { GUID filterType; GUID calloutKey; }（BLOCK 动作不使用）
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_FILTER0
    {
        public Guid FilterKey;
        public FWPM_DISPLAY_DATA0 DisplayData;
        public uint Flags;
        public IntPtr ProviderKey;      // GUID*
        public FWP_BYTE_BLOB ProviderData;
        public Guid LayerKey;
        public Guid SubLayerKey;
        public FWP_VALUE0 Weight;
        public uint NumFilterConditions;
        public IntPtr FilterCondition;  // FWPM_FILTER_CONDITION0*
        public FWPM_ACTION0 Action;
        public ulong RawContext;        // union { UINT64 rawContext; GUID* providerContextKey; }
        public IntPtr Reserved;         // GUID*
        public ulong FilterId;
        public FWP_VALUE0 EffectiveWeight;
    }

    /// <summary>按 fwpmtypes.h 的真实定义：flags 是 UINT32，providerData 在 providerKey 之后，weight 是结尾的 UINT16。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_SUBLAYER0
    {
        public Guid SubLayerKey;
        public FWPM_DISPLAY_DATA0 DisplayData;
        public uint Flags;              // 不设 PERSISTENT：重启后自动清除，由配置重建
        public IntPtr ProviderKey;      // GUID*
        public FWP_BYTE_BLOB ProviderData;
        public ushort Weight;           // 子层权重，越大越先评估
    }

    internal const int ExpectedFwpmSession0SizeX64 = 72;
    internal const int ExpectedFwpmProvider0SizeX64 = 64;
    internal const int ExpectedFwpmCallout0SizeX64 = 88;
    internal const int ExpectedFwpmFilter0SizeX64 = 192;

    internal static bool ValidateStrictInteropLayout()
        => IntPtr.Size != 8 || Marshal.SizeOf<FWPM_SESSION0>() == ExpectedFwpmSession0SizeX64
            && Marshal.SizeOf<FWPM_PROVIDER0>() == ExpectedFwpmProvider0SizeX64
            && Marshal.SizeOf<FWPM_CALLOUT0>() == ExpectedFwpmCallout0SizeX64
            && Marshal.SizeOf<FWPM_SUBLAYER0>() == 72
            && Marshal.SizeOf<FWPM_FILTER0>() == ExpectedFwpmFilter0SizeX64;

    [DllImport("fwpuclnt.dll")]
    internal static extern uint FwpmEngineOpen0(IntPtr serverName, uint authnService, IntPtr authIdentity,
        IntPtr session, out IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    internal static extern uint FwpmEngineClose0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    internal static extern uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);

    [DllImport("fwpuclnt.dll")]
    internal static extern uint FwpmTransactionCommit0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    internal static extern uint FwpmTransactionAbort0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    internal static extern uint FwpmSubLayerAdd0(IntPtr engineHandle, ref FWPM_SUBLAYER0 subLayer, IntPtr sd);

    [DllImport("fwpuclnt.dll")]
    internal static extern uint FwpmFilterAdd0(IntPtr engineHandle, ref FWPM_FILTER0 filter, IntPtr sd,
        out ulong id);

    [DllImport("fwpuclnt.dll")]
    internal static extern uint FwpmFilterEnable0(IntPtr engineHandle, ulong id);

    [DllImport("fwpuclnt.dll")]
    internal static extern uint FwpmFilterDisable0(IntPtr engineHandle, ulong id);

    [DllImport("fwpuclnt.dll")]
    internal static extern uint FwpmFilterDeleteByKey0(IntPtr engineHandle, ref Guid key);

    [DllImport("fwpuclnt.dll")]
    internal static extern uint FwpmProviderAdd0(IntPtr engineHandle, ref FWPM_PROVIDER0 provider, IntPtr sd);

    [DllImport("fwpuclnt.dll")]
    internal static extern uint FwpmCalloutAdd0(IntPtr engineHandle, ref FWPM_CALLOUT0 callout, IntPtr sd, out uint calloutId);

    [DllImport("fwpuclnt.dll")]
    internal static extern uint FwpmCalloutDeleteByKey0(IntPtr engineHandle, ref Guid key);

    [DllImport("fwpuclnt.dll")]
    internal static extern uint FwpmSubLayerDeleteByKey0(IntPtr engineHandle, ref Guid key);

    [DllImport("fwpuclnt.dll")]
    internal static extern uint FwpmProviderDeleteByKey0(IntPtr engineHandle, ref Guid key);

    [DllImport("fwpuclnt.dll")]
    internal static extern uint FwpmGetAppIdFromFileName0(
        [MarshalAs(UnmanagedType.LPWStr)] string fileName, out IntPtr appId);

    [DllImport("fwpuclnt.dll")]
    internal static extern uint FwpmFreeMemory0(ref IntPtr p);
}
