using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using NetWatch.Core.Wfp;

namespace NetWatch.StrictService;

internal sealed class StrictWfpFilterManager : IDisposable
{
    private const uint RpcAuthnWinnt = 10;
    private static readonly Guid ProviderKey = new("2B9BA321-5907-4652-AC01-9A7E8048F05B");
    private static readonly Guid SubLayerKey = new("6E62A175-AD01-4CC5-B3B1-682F5A307928");
    private static readonly Guid FlowV4 = new("D8A1E037-5294-4B2F-92AD-34775D930E11");
    private static readonly Guid FlowV6 = new("B1E1976A-10C6-40C2-8532-521C04732D60");
    private static readonly Guid TransportV4 = new("478F21F0-3E8A-43EE-9784-14DC25C6885B");
    private static readonly Guid TransportV6 = new("F1AB0340-78E3-47B6-A02A-DAE3F1957E96");
    private static readonly Guid[] FilterKeys =
    {
        new("CE6EA14F-1C79-46F0-97E6-D7AC70460717"),
        new("E8D7C0C4-1E71-4F18-9A5B-373A2B1B140A"),
        new("7E73DC1D-7A30-4FD8-99FB-5631E3477D17"),
        new("662ED09D-A9D4-4F51-BC7B-8CB850A023A9"),
    };

    private IntPtr _engine;
    private readonly ulong[] _filterIds = new ulong[4];
    private readonly object _gate = new();
    private bool _disposed;
    private bool _filtersEnabled;
    public bool IsInstalled { get; private set; }
    public bool FiltersEnabled { get { lock (_gate) return _filtersEnabled; } }

    public StrictWfpFilterManager()
    {
        if (!WfpNative.ValidateStrictInteropLayout())
            throw new InvalidOperationException("WFP interop structure layout does not match the Windows x64 ABI.");
        var sessionName = Marshal.StringToHGlobalUni("NetWatch Strict Upload (disabled filters)");
        var session = new WfpNative.FWPM_SESSION0
        {
            SessionKey = Guid.NewGuid(),
            DisplayData = new WfpNative.FWPM_DISPLAY_DATA0 { Name = sessionName },
            Flags = WfpNative.FWPM_SESSION_FLAG_DYNAMIC,
            TxnWaitTimeoutInMSec = 5000,
        };
        var sessionPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WfpNative.FWPM_SESSION0>());
        try
        {
            Marshal.StructureToPtr(session, sessionPtr, false);
            var status = WfpNative.FwpmEngineOpen0(IntPtr.Zero, RpcAuthnWinnt, IntPtr.Zero,
                sessionPtr, out _engine);
            if (status != 0) throw new InvalidOperationException($"创建动态 WFP session 失败 (0x{status:X8})。");
            InstallDisabledObjects();
            IsInstalled = true;
        }
        catch
        {
            if (_engine != IntPtr.Zero) { WfpNative.FwpmEngineClose0(_engine); _engine = IntPtr.Zero; }
            throw;
        }
        finally
        {
            Marshal.DestroyStructure<WfpNative.FWPM_SESSION0>(sessionPtr);
            Marshal.FreeHGlobal(sessionPtr);
            Marshal.FreeHGlobal(sessionName);
        }
    }

    private void InstallDisabledObjects()
    {
        var status = WfpNative.FwpmTransactionBegin0(_engine, 0);
        if (status != 0) throw new InvalidOperationException($"开始 WFP transaction 失败 (0x{status:X8})。");
        var committed = false;
        var providerName = Marshal.StringToHGlobalUni("NetWatch Strict Upload");
        var providerService = Marshal.StringToHGlobalUni("NetWatchStrictService");
        var subLayerName = Marshal.StringToHGlobalUni("NetWatch Strict Upload (disabled)");
        var calloutName = Marshal.StringToHGlobalUni("NetWatch Strict Upload Callout");
        try
        {
            var provider = new WfpNative.FWPM_PROVIDER0
            {
                ProviderKey = ProviderKey,
                DisplayData = new WfpNative.FWPM_DISPLAY_DATA0 { Name = providerName },
                ServiceName = providerService,
            };
            status = WfpNative.FwpmProviderAdd0(_engine, ref provider, IntPtr.Zero);
            if (status != 0)
                throw new InvalidOperationException($"注册 WFP provider 失败 (0x{status:X8})。");

            var providerKeyPtr = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
            try
            {
                Marshal.StructureToPtr(ProviderKey, providerKeyPtr, false);
                var subLayer = new WfpNative.FWPM_SUBLAYER0
                {
                    SubLayerKey = SubLayerKey,
                    DisplayData = new WfpNative.FWPM_DISPLAY_DATA0 { Name = subLayerName },
                    ProviderKey = providerKeyPtr,
                    Weight = 0x7000,
                };
                status = WfpNative.FwpmSubLayerAdd0(_engine, ref subLayer, IntPtr.Zero);
                if (status != 0)
                    throw new InvalidOperationException($"注册 WFP sublayer 失败 (0x{status:X8})。");

                AddCallout(FlowV4, WfpNative.LayerAleFlowEstablishedV4, calloutName, providerKeyPtr);
                AddCallout(FlowV6, WfpNative.LayerAleFlowEstablishedV6, calloutName, providerKeyPtr);
                AddCallout(TransportV4, WfpNative.LayerOutboundTransportV4, calloutName, providerKeyPtr);
                AddCallout(TransportV6, WfpNative.LayerOutboundTransportV6, calloutName, providerKeyPtr);
                AddDisabledFilter(0, FilterKeys[0], WfpNative.LayerAleFlowEstablishedV4, FlowV4, providerKeyPtr, calloutName);
                AddDisabledFilter(1, FilterKeys[1], WfpNative.LayerAleFlowEstablishedV6, FlowV6, providerKeyPtr, calloutName);
                AddDisabledFilter(2, FilterKeys[2], WfpNative.LayerOutboundTransportV4, TransportV4, providerKeyPtr, calloutName);
                AddDisabledFilter(3, FilterKeys[3], WfpNative.LayerOutboundTransportV6, TransportV6, providerKeyPtr, calloutName);
            }
            finally { Marshal.FreeHGlobal(providerKeyPtr); }

            status = WfpNative.FwpmTransactionCommit0(_engine);
            if (status != 0) throw new InvalidOperationException($"提交 WFP transaction 失败 (0x{status:X8})。");
            committed = true;
        }
        finally
        {
            Marshal.FreeHGlobal(providerName);
            Marshal.FreeHGlobal(providerService);
            Marshal.FreeHGlobal(subLayerName);
            Marshal.FreeHGlobal(calloutName);
            if (!committed) WfpNative.FwpmTransactionAbort0(_engine);
        }
    }

    private void AddCallout(Guid key, Guid layer, IntPtr name, IntPtr providerKey)
    {
        var callout = new WfpNative.FWPM_CALLOUT0
        {
            CalloutKey = key,
            DisplayData = new WfpNative.FWPM_DISPLAY_DATA0 { Name = name },
            ProviderKey = providerKey,
            ApplicableLayer = layer,
        };
        var status = WfpNative.FwpmCalloutAdd0(_engine, ref callout, IntPtr.Zero, out _);
        if (status != 0)
            throw new InvalidOperationException($"注册 WFP callout 失败 (0x{status:X8})。");
    }

    private void AddDisabledFilter(int index, Guid filterKey, Guid layer, Guid callout, IntPtr providerKey, IntPtr name)
    {
        var action = new WfpNative.FWPM_ACTION0
        {
            Type = WfpNative.FWP_ACTION_CALLOUT_TERMINATING,
            Union = callout,
        };
        var filter = new WfpNative.FWPM_FILTER0
        {
            FilterKey = filterKey,
            DisplayData = new WfpNative.FWPM_DISPLAY_DATA0 { Name = name },
            Flags = WfpNative.FWPM_FILTER_FLAG_DISABLED,
            ProviderKey = providerKey,
            LayerKey = layer,
            SubLayerKey = SubLayerKey,
            Weight = new WfpNative.FWP_VALUE0 { Type = WfpNative.FWP_EMPTY },
            Action = action,
        };
        var status = WfpNative.FwpmFilterAdd0(_engine, ref filter, IntPtr.Zero, out var filterId);
        if (status != 0 || filterId == 0)
            throw new InvalidOperationException($"添加禁用 WFP filter 失败 (0x{status:X8})。");
        _filterIds[index] = filterId;
    }

    public void SetFiltersEnabled(bool enabled)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_filtersEnabled == enabled) return;
            var status = WfpNative.FwpmTransactionBegin0(_engine, 0);
            if (status != 0) throw new InvalidOperationException($"开始 WFP filter 状态事务失败 (0x{status:X8})。");
            var committed = false;
            try
            {
                foreach (var id in _filterIds)
                {
                    status = enabled
                        ? WfpNative.FwpmFilterEnable0(_engine, id)
                        : WfpNative.FwpmFilterDisable0(_engine, id);
                    if (status != 0)
                        throw new InvalidOperationException($"切换 WFP filter 状态失败 (0x{status:X8})。");
                }
                status = WfpNative.FwpmTransactionCommit0(_engine);
                if (status != 0) throw new InvalidOperationException($"提交 WFP filter 状态事务失败 (0x{status:X8})。");
                committed = true;
                _filtersEnabled = enabled;
            }
            finally
            {
                if (!committed) WfpNative.FwpmTransactionAbort0(_engine);
            }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            if (_engine != IntPtr.Zero)
            {
                WfpNative.FwpmEngineClose0(_engine);
                _engine = IntPtr.Zero;
            }
            IsInstalled = false;
        }
    }

}
