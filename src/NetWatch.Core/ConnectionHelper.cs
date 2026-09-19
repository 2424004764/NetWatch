using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;

namespace NetWatch.Core;

public sealed record ConnectionInfo(string Protocol, string Local, string Remote, string State, int Pid);

/// <summary>
/// 通过 IP Helper API（GetExtendedTcpTable / GetExtendedUdpTable）枚举系统当前
/// 所有 TCP/UDP 连接及其归属进程，用于“连接详情”视图与列表中的连接数列。
/// </summary>
public static class ConnectionHelper
{
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;
    private const uint MIB_TCP_STATE_LISTEN = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint State, LocalAddr, LocalPort, RemoteAddr, RemotePort, OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] LocalAddr;
        public uint LocalScopeId, LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] RemoteAddr;
        public uint RemoteScopeId, RemotePort, State, OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint LocalAddr, LocalPort, OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] LocalAddr;
        public uint LocalScopeId, LocalPort, OwningPid;
    }

    [DllImport("iphlpapi.dll")]
    private static extern int GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, int reserved);

    [DllImport("iphlpapi.dll")]
    private static extern int GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, int reserved);

    public static List<ConnectionInfo> GetConnections(HashSet<int>? filterPids = null)
    {
        var list = new List<ConnectionInfo>(128);

        foreach (var r in ReadTable<MIB_TCPROW_OWNER_PID>(true, AF_INET, TCP_TABLE_OWNER_PID_ALL))
        {
            int pid = (int)r.OwningPid;
            if (filterPids != null && !filterPids.Contains(pid)) continue;
            list.Add(new ConnectionInfo("TCP",
                EndPoint(r.LocalAddr, r.LocalPort),
                r.State == MIB_TCP_STATE_LISTEN ? "*" : EndPoint(r.RemoteAddr, r.RemotePort),
                TcpStateName(r.State), pid));
        }
        foreach (var r in ReadTable<MIB_TCP6ROW_OWNER_PID>(true, AF_INET6, TCP_TABLE_OWNER_PID_ALL))
        {
            int pid = (int)r.OwningPid;
            if (filterPids != null && !filterPids.Contains(pid)) continue;
            list.Add(new ConnectionInfo("TCP",
                EndPoint6(r.LocalAddr, r.LocalScopeId, r.LocalPort),
                r.State == MIB_TCP_STATE_LISTEN ? "*" : EndPoint6(r.RemoteAddr, r.RemoteScopeId, r.RemotePort),
                TcpStateName(r.State), pid));
        }
        foreach (var r in ReadTable<MIB_UDPROW_OWNER_PID>(false, AF_INET, UDP_TABLE_OWNER_PID))
        {
            int pid = (int)r.OwningPid;
            if (filterPids != null && !filterPids.Contains(pid)) continue;
            list.Add(new ConnectionInfo("UDP", EndPoint(r.LocalAddr, r.LocalPort), "*", "—", pid));
        }
        foreach (var r in ReadTable<MIB_UDP6ROW_OWNER_PID>(false, AF_INET6, UDP_TABLE_OWNER_PID))
        {
            int pid = (int)r.OwningPid;
            if (filterPids != null && !filterPids.Contains(pid)) continue;
            list.Add(new ConnectionInfo("UDP", EndPoint6(r.LocalAddr, r.LocalScopeId, r.LocalPort), "*", "—", pid));
        }
        return list;
    }

    private static List<T> ReadTable<T>(bool tcp, int af, int tableClass) where T : struct
    {
        int size = 0;
        int rc = tcp
            ? GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, tableClass, 0)
            : GetExtendedUdpTable(IntPtr.Zero, ref size, false, af, tableClass, 0);
        if (rc != 0 && rc != 122 /* ERROR_INSUFFICIENT_BUFFER */) return new List<T>();

        var buf = Marshal.AllocHGlobal(size);
        try
        {
            rc = tcp
                ? GetExtendedTcpTable(buf, ref size, false, af, tableClass, 0)
                : GetExtendedUdpTable(buf, ref size, false, af, tableClass, 0);
            if (rc != 0) return new List<T>();

            int count = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<T>();
            long first = buf.ToInt64() + 4;
            var rows = new List<T>(count);
            for (int i = 0; i < count; i++)
                rows.Add(Marshal.PtrToStructure<T>((IntPtr)(first + (long)i * rowSize)));
            return rows;
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static string EndPoint(uint addr, uint portNet) => Ip4(addr) + ":" + Port(portNet);

    private static string EndPoint6(byte[] addr, uint scope, uint portNet)
        => "[" + new IPAddress(addr, scope).ToString() + "]:" + Port(portNet);

    private static string Ip4(uint v)
    {
        // 表里的 IPv4 地址是网络序 4 字节；在小端机器上读出的整数低位字节是第一段
        return (v & 0xFF) + "." + ((v >> 8) & 0xFF) + "." + ((v >> 16) & 0xFF) + "." + ((v >> 24) & 0xFF);
    }

    private static int Port(uint net) => (int)(((net & 0xFF) << 8) | ((net >> 8) & 0xFF));

    private static string TcpStateName(uint s) => s >= 1 && s < TcpStates.Length ? TcpStates[s] : "未知";

    private static readonly string[] TcpStates =
    {
        "", "关闭", "监听", "等待连接", "接收连接", "已建立",
        "FIN等待1", "FIN等待2", "关闭等待", "正在关闭", "最后确认", "TIME等待", "删除TCB",
    };
}
