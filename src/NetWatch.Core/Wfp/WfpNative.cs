using System;
using System.Runtime.InteropServices;

namespace NetWatch.Core.Wfp;

/// <summary>WFP（Windows 筛选平台）本机 API 的互操作定义。仅声明“添加/删除出站屏蔽过滤器”所需的最小集合。</summary>
internal static class WfpNative
{
    // FWP_ACTION_TYPE
    internal const uint FWP_ACTION_BLOCK = 0x1001; // 0x1 | FWP_ACTION_FLAG_TERMINATING

    // FWP_DATA_TYPE（本实现用到的）
    internal const uint FWP_EMPTY = 0;
    internal const uint FWP_UINT64 = 4;
    internal const uint FWP_BYTE_BLOB_TYPE = 12;
    internal const uint FWP_V4_ADDR_MASK = 0x100;
    internal const uint FWP_V6_ADDR_MASK = 0x101;

    internal const uint RPC_C_AUTHN_WINNT = 10;
    internal const uint FWP_E_ALREADY_EXISTS = 0x80320009;
    internal const uint FWP_MATCH_EQUAL = 0;

    /// <summary>连接授权层（IPv4）：拦截 connect()/sendto() 目的地址的匹配。</summary>
    internal static readonly Guid LayerAleAuthConnectV4 = new("C38D57D1-05A7-4C33-904F-7FBCEEE60E82");
    /// <summary>连接授权层（IPv6）。</summary>
    internal static readonly Guid LayerAleAuthConnectV6 = new("4A72393B-319F-44BC-84C3-BA54DCB3B6B4");
    /// <summary>条件：发起连接的应用程序（NT 设备路径 blob）。</summary>
    internal static readonly Guid ConditionAleAppId = new("D78E1E87-8644-4EA5-9437-D809ECEFC971");
    /// <summary>条件：远程 IP 地址（支持掩码/网段）。</summary>
    internal static readonly Guid ConditionIpRemoteAddress = new("B235AE9A-1D64-49B8-A44C-5FF3D9095045");

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
    internal static extern uint FwpmFilterDeleteByKey0(IntPtr engineHandle, ref Guid key);

    [DllImport("fwpuclnt.dll")]
    internal static extern uint FwpmGetAppIdFromFileName0(
        [MarshalAs(UnmanagedType.LPWStr)] string fileName, out IntPtr appId);

    [DllImport("fwpuclnt.dll")]
    internal static extern uint FwpmFreeMemory0(ref IntPtr p);
}
