using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace AegisScanner
{
    public class MalwareDb
    {
        [JsonPropertyName("version")]
        public string Version { get; set; } = "2026.11.17";

        [JsonPropertyName("sha256_signatures")]
        public Dictionary<string, ShaSignature> Sha256Signatures { get; set; } = new();

        [JsonPropertyName("malicious_dll_names")]
        public List<string> MaliciousDllNames { get; set; } = new();

        [JsonPropertyName("byovd_driver_names")]
        public List<string> ByovdDriverNames { get; set; } = new();

        [JsonPropertyName("hijackable_system_dlls")]
        public List<string> HijackableSystemDlls { get; set; } = new();

        [JsonPropertyName("byte_patterns")]
        public List<BytePattern> BytePatterns { get; set; } = new();

        [JsonPropertyName("suspicious_extensions")]
        public List<string> SuspiciousExtensions { get; set; } = new();

        [JsonPropertyName("suspicious_process_names")]
        public List<string> SuspiciousProcessNames { get; set; } = new();

        [JsonPropertyName("suspicious_ports")]
        public List<int> SuspiciousPorts { get; set; } = new();

        [JsonIgnore]
        public HashSet<string> MaliciousDllSet { get; private set; } = new(StringComparer.OrdinalIgnoreCase);

        [JsonIgnore]
        public HashSet<string> ByovdDriverSet { get; private set; } = new(StringComparer.OrdinalIgnoreCase);

        [JsonIgnore]
        public HashSet<string> HijackableDllSet { get; private set; } = new(StringComparer.OrdinalIgnoreCase);

        [JsonIgnore]
        public HashSet<string> SuspiciousExtSet { get; private set; } = new(StringComparer.OrdinalIgnoreCase);

        [JsonIgnore]
        public HashSet<int> SuspiciousPortSet { get; private set; } = new();

        [JsonIgnore]
        public string[] SuspiciousProcessNamesLower { get; private set; } = Array.Empty<string>();

        public void BuildIndexes()
        {
            MaliciousDllSet = new HashSet<string>(
                MaliciousDllNames.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()),
                StringComparer.OrdinalIgnoreCase);
            ByovdDriverSet = new HashSet<string>(
                ByovdDriverNames.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()),
                StringComparer.OrdinalIgnoreCase);
            HijackableDllSet = new HashSet<string>(
                HijackableSystemDlls.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()),
                StringComparer.OrdinalIgnoreCase);
            SuspiciousExtSet = new HashSet<string>(
                SuspiciousExtensions.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()),
                StringComparer.OrdinalIgnoreCase);
            SuspiciousPortSet = new HashSet<int>(SuspiciousPorts);
            SuspiciousProcessNamesLower = SuspiciousProcessNames
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim().ToLowerInvariant())
                .ToArray();
        }
    }

    public class ShaSignature
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = "";
        [JsonPropertyName("severity")]
        public string Severity { get; set; } = "HIGH";
        [JsonPropertyName("category")]
        public string Category { get; set; } = "";
        [JsonPropertyName("description")]
        public string Description { get; set; } = "";
    }

    public class BytePattern
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = "";
        [JsonPropertyName("pattern")]
        public string Pattern { get; set; } = "";
        [JsonPropertyName("name")]
        public string Name { get; set; } = "";
        [JsonPropertyName("severity")]
        public string Severity { get; set; } = "HIGH";
        [JsonPropertyName("score")]
        public int Score { get; set; }
        [JsonPropertyName("category")]
        public string Category { get; set; } = "";
        [JsonPropertyName("description")]
        public string Description { get; set; } = "";
    }

    public class ScanResultItem
    {
        [JsonPropertyName("path")]
        public string Path { get; set; } = "";
        [JsonPropertyName("file_name")]
        public string FileName { get; set; } = "";
        [JsonPropertyName("size_bytes")]
        public long SizeBytes { get; set; }
        [JsonPropertyName("sha256")]
        public string Sha256 { get; set; } = "";
        [JsonPropertyName("entropy")]
        public double Entropy { get; set; }
        [JsonPropertyName("is_pe")]
        public bool IsPe { get; set; }
        [JsonPropertyName("is_signed")]
        public bool IsSigned { get; set; }
        [JsonPropertyName("signer")]
        public string Signer { get; set; } = "";
        [JsonPropertyName("status")]
        public string Status { get; set; } = "CLEAN";
        [JsonPropertyName("threat_name")]
        public string ThreatName { get; set; } = "";
        [JsonPropertyName("severity")]
        public string Severity { get; set; } = "SAFE";
        [JsonPropertyName("risk_score")]
        public int RiskScore { get; set; }
        [JsonPropertyName("detection_stage")]
        public string DetectionStage { get; set; } = "Temiz (Tüm Aşamalar Geçildi)";
        [JsonPropertyName("reasons")]
        public List<string> Reasons { get; set; } = new();
        [JsonPropertyName("engine")]
        public string Engine { get; set; } = "Core 1.0";
    }

    public class ScanSummary
    {
        [JsonPropertyName("engine")]
        public string Engine { get; set; } = "Core 1.0";
        [JsonPropertyName("target")]
        public string Target { get; set; } = "";
        [JsonPropertyName("total_files_scanned")]
        public int TotalFilesScanned { get; set; }
        [JsonPropertyName("total_bytes_scanned")]
        public long TotalBytesScanned { get; set; }
        [JsonPropertyName("threats_found")]
        public int ThreatsFound { get; set; }
        [JsonPropertyName("suspicious_found")]
        public int SuspiciousFound { get; set; }
        [JsonPropertyName("duration_ms")]
        public long DurationMs { get; set; }
        [JsonPropertyName("files_per_second")]
        public double FilesPerSecond { get; set; }
        [JsonPropertyName("detections")]
        public List<ScanResultItem> Detections { get; set; } = new();
        [JsonPropertyName("scanned_files")]
        public List<ScanResultItem> ScannedFiles { get; set; } = new();
    }

    public class ProcessItem
    {
        [JsonPropertyName("pid")]
        public int Pid { get; set; }
        [JsonPropertyName("name")]
        public string Name { get; set; } = "";
        [JsonPropertyName("path")]
        public string Path { get; set; } = "";
        [JsonPropertyName("is_signed")]
        public bool IsSigned { get; set; }
        [JsonPropertyName("memory_mb")]
        public double MemoryMb { get; set; }
        [JsonPropertyName("threads")]
        public int Threads { get; set; }
        [JsonPropertyName("risk_score")]
        public int RiskScore { get; set; }
        [JsonPropertyName("status")]
        public string Status { get; set; } = "CLEAN";
        [JsonPropertyName("reasons")]
        public List<string> Reasons { get; set; } = new();
    }

    public class NetworkConnectionItem
    {
        [JsonPropertyName("pid")]
        public int Pid { get; set; }
        [JsonPropertyName("process_name")]
        public string ProcessName { get; set; } = "";
        [JsonPropertyName("local_address")]
        public string LocalAddress { get; set; } = "";
        [JsonPropertyName("local_port")]
        public int LocalPort { get; set; }
        [JsonPropertyName("remote_address")]
        public string RemoteAddress { get; set; } = "";
        [JsonPropertyName("remote_port")]
        public int RemotePort { get; set; }
        [JsonPropertyName("state")]
        public string State { get; set; } = "";
        [JsonPropertyName("is_suspicious")]
        public bool IsSuspicious { get; set; }
        [JsonPropertyName("reason")]
        public string Reason { get; set; } = "";
        [JsonPropertyName("executable_path")]
        public string ExecutablePath { get; set; } = "";
        [JsonPropertyName("is_signed")]
        public bool IsSigned { get; set; }
        [JsonPropertyName("risk_score")]
        public int RiskScore { get; set; }
    }

    public class ProcessNetReport
    {
        [JsonPropertyName("engine")]
        public string Engine { get; set; } = "AegisCore C# .NET 8 Process & Kernel Socket Radar";
        [JsonPropertyName("total_processes")]
        public int TotalProcesses { get; set; }
        [JsonPropertyName("suspicious_processes")]
        public int SuspiciousProcesses { get; set; }
        [JsonPropertyName("active_connections")]
        public int ActiveConnections { get; set; }
        [JsonPropertyName("suspicious_connections")]
        public int SuspiciousConnections { get; set; }
        [JsonPropertyName("processes")]
        public List<ProcessItem> Processes { get; set; } = new();
        [JsonPropertyName("connections")]
        public List<NetworkConnectionItem> Connections { get; set; } = new();
    }

    internal static class NativeNetHelper
    {
        private const int AF_INET = 2;
        private const int AF_INET6 = 23;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;
        private const int UDP_TABLE_OWNER_PID = 1;

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDPROW_OWNER_PID
        {
            public uint localAddr;
            public byte localPort1;
            public byte localPort2;
            public byte localPort3;
            public byte localPort4;
            public int owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] localAddr;
            public uint localScopeId;
            public byte localPort1;
            public byte localPort2;
            public byte localPort3;
            public byte localPort4;
            public int owningPid;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedUdpTable(
            IntPtr pUdpTable,
            ref int pdwSize,
            bool bOrder,
            int ulAf,
            int TableClass,
            uint Reserved);

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public byte localPort1;
            public byte localPort2;
            public byte localPort3;
            public byte localPort4;
            public uint remoteAddr;
            public byte remotePort1;
            public byte remotePort2;
            public byte remotePort3;
            public byte remotePort4;
            public int owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] localAddr;
            public uint localScopeId;
            public byte localPort1;
            public byte localPort2;
            public byte localPort3;
            public byte localPort4;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] remoteAddr;
            public uint remoteScopeId;
            public byte remotePort1;
            public byte remotePort2;
            public byte remotePort3;
            public byte remotePort4;
            public uint state;
            public int owningPid;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref int pdwSize,
            bool bOrder,
            int ulAf,
            int TableClass,
            uint Reserved);

        private static string TcpStateName(uint state) => state switch
        {
            1 => "CLOSED",
            2 => "LISTEN",
            3 => "SYN_SENT",
            4 => "SYN_RCVD",
            5 => "ESTABLISHED",
            6 => "FIN_WAIT1",
            7 => "FIN_WAIT2",
            8 => "CLOSE_WAIT",
            9 => "CLOSING",
            10 => "LAST_ACK",
            11 => "TIME_WAIT",
            12 => "DELETE_TCB",
            _ => "UNKNOWN"
        };

        public static List<(int Pid, string LocalAddr, int LocalPort, string RemoteAddr, int RemotePort, string State)> GetTcpConnectionsWithPid()
        {
            var results = new List<(int, string, int, string, int, string)>();
            const int MaxTableBytes = 64 * 1024 * 1024;

            // IPv4 TCP tablosu
            int buffSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref buffSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            for (int attempt = 0; attempt < 3 && buffSize > 0 && buffSize <= MaxTableBytes; attempt++)
            {
                IntPtr tcpTablePtr = Marshal.AllocHGlobal(buffSize);
                try
                {
                    uint rc = GetExtendedTcpTable(tcpTablePtr, ref buffSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                    if (rc == 122) continue; // ERROR_INSUFFICIENT_BUFFER
                    if (rc == 0 && buffSize >= 4)
                    {
                        int rowCount = Marshal.ReadInt32(tcpTablePtr);
                        int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                        if (rowCount >= 0 && 4L + (long)rowCount * rowSize <= buffSize)
                        {
                            IntPtr rowPtr = IntPtr.Add(tcpTablePtr, 4);
                            for (int i = 0; i < rowCount; i++)
                            {
                                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                                var localIp = new IPAddress(row.localAddr).ToString();
                                var remoteIp = new IPAddress(row.remoteAddr).ToString();
                                int localPort = (row.localPort1 << 8) + row.localPort2;
                                int remotePort = row.remoteAddr == 0 ? 0 : (row.remotePort1 << 8) + row.remotePort2;
                                results.Add((row.owningPid, localIp, localPort, remoteIp, remotePort, TcpStateName(row.state)));
                                rowPtr = IntPtr.Add(rowPtr, rowSize);
                            }
                        }
                    }
                    break;
                }
                finally
                {
                    Marshal.FreeHGlobal(tcpTablePtr);
                }
            }

            // IPv6 TCP tablosu
            try
            {
                int buffSize6 = 0;
                GetExtendedTcpTable(IntPtr.Zero, ref buffSize6, true, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
                for (int attempt = 0; attempt < 3 && buffSize6 > 0 && buffSize6 <= MaxTableBytes; attempt++)
                {
                    IntPtr tcpTablePtr6 = Marshal.AllocHGlobal(buffSize6);
                    try
                    {
                        uint rc6 = GetExtendedTcpTable(tcpTablePtr6, ref buffSize6, true, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
                        if (rc6 == 122) continue; // ERROR_INSUFFICIENT_BUFFER
                        if (rc6 == 0 && buffSize6 >= 4)
                        {
                            int rowCount6 = Marshal.ReadInt32(tcpTablePtr6);
                            int rowSize6 = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();
                            if (rowCount6 >= 0 && 4L + (long)rowCount6 * rowSize6 <= buffSize6)
                            {
                                IntPtr rowPtr6 = IntPtr.Add(tcpTablePtr6, 4);
                                for (int i = 0; i < rowCount6; i++)
                                {
                                    var row6 = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr6);
                                    var localIp = new IPAddress(row6.localAddr).ToString();
                                    var remoteIp = new IPAddress(row6.remoteAddr).ToString();
                                    bool remoteZero = Array.TrueForAll(row6.remoteAddr, b => b == 0);
                                    int localPort = (row6.localPort1 << 8) + row6.localPort2;
                                    int remotePort = remoteZero ? 0 : (row6.remotePort1 << 8) + row6.remotePort2;
                                    results.Add((row6.owningPid, localIp, localPort, remoteIp, remotePort, TcpStateName(row6.state)));
                                    rowPtr6 = IntPtr.Add(rowPtr6, rowSize6);
                                }
                            }
                        }
                        break;
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(tcpTablePtr6);
                    }
                }
            }
            catch { }

            return results;
        }

        public static List<(int Pid, string LocalAddr, int LocalPort)> GetUdpEndpointsWithPid()
        {
            var results = new List<(int, string, int)>();
            const int MaxTableBytes = 64 * 1024 * 1024;
            try
            {
                int buffSize = 0;
                GetExtendedUdpTable(IntPtr.Zero, ref buffSize, true, AF_INET, UDP_TABLE_OWNER_PID, 0);
                for (int attempt = 0; attempt < 3 && buffSize > 0 && buffSize <= MaxTableBytes; attempt++)
                {
                    IntPtr ptr = Marshal.AllocHGlobal(buffSize);
                    try
                    {
                        uint rc = GetExtendedUdpTable(ptr, ref buffSize, true, AF_INET, UDP_TABLE_OWNER_PID, 0);
                        if (rc == 122) continue;
                        if (rc == 0 && buffSize >= 4)
                        {
                            int rowCount = Marshal.ReadInt32(ptr);
                            int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();
                            if (rowCount >= 0 && 4L + (long)rowCount * rowSize <= buffSize)
                            {
                                IntPtr rowPtr = IntPtr.Add(ptr, 4);
                                for (int i = 0; i < rowCount; i++)
                                {
                                    var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                                    var localIp = new IPAddress(row.localAddr).ToString();
                                    int localPort = (row.localPort1 << 8) + row.localPort2;
                                    results.Add((row.owningPid, localIp, localPort));
                                    rowPtr = IntPtr.Add(rowPtr, rowSize);
                                }
                            }
                        }
                        break;
                    }
                    finally { Marshal.FreeHGlobal(ptr); }
                }

                int buffSize6 = 0;
                GetExtendedUdpTable(IntPtr.Zero, ref buffSize6, true, AF_INET6, UDP_TABLE_OWNER_PID, 0);
                for (int attempt = 0; attempt < 3 && buffSize6 > 0 && buffSize6 <= MaxTableBytes; attempt++)
                {
                    IntPtr ptr6 = Marshal.AllocHGlobal(buffSize6);
                    try
                    {
                        uint rc6 = GetExtendedUdpTable(ptr6, ref buffSize6, true, AF_INET6, UDP_TABLE_OWNER_PID, 0);
                        if (rc6 == 122) continue;
                        if (rc6 == 0 && buffSize6 >= 4)
                        {
                            int rowCount6 = Marshal.ReadInt32(ptr6);
                            int rowSize6 = Marshal.SizeOf<MIB_UDP6ROW_OWNER_PID>();
                            if (rowCount6 >= 0 && 4L + (long)rowCount6 * rowSize6 <= buffSize6)
                            {
                                IntPtr rowPtr6 = IntPtr.Add(ptr6, 4);
                                for (int i = 0; i < rowCount6; i++)
                                {
                                    var row6 = Marshal.PtrToStructure<MIB_UDP6ROW_OWNER_PID>(rowPtr6);
                                    var localIp = new IPAddress(row6.localAddr).ToString();
                                    int localPort = (row6.localPort1 << 8) + row6.localPort2;
                                    results.Add((row6.owningPid, localIp, localPort));
                                    rowPtr6 = IntPtr.Add(rowPtr6, rowSize6);
                                }
                            }
                        }
                        break;
                    }
                    finally { Marshal.FreeHGlobal(ptr6); }
                }
            }
            catch { }
            return results;
        }
    }

    class Program
    {
        static string ActiveTier = "pro";
        static string ActiveEngineName => "SuperLX 1.0";

        static readonly TimeSpan RxTimeout = TimeSpan.FromMilliseconds(250);

        // Compiled static patterns with strict ReDoS timeouts and bounded quantifiers
        static readonly Regex RxLnkWeaponized = new Regex(
            @"(?:(?:powershell|pwsh)(?:\.exe)?\s+.{0,300}?(?:-enc|-e\s|iex|iwr|irm|downloadstring|downloadfile|frombase64|http)|mshta(?:\.exe)?\s+(?:http|vbscript:|javascript:)|cmd(?:\.exe)?\s+/[ck]\s+.{0,300}?(?:curl|bitsadmin|certutil|mshta|powershell|wscript|cscript|%comspec%)|(?:forfiles|pcalua|odbcconf|cmstp|msiexec)(?:\.exe)?\s+.{0,300}?(?:http|regsvr|cmd|powershell))",
            RegexOptions.Compiled | RegexOptions.IgnoreCase, RxTimeout);
        static readonly Regex RxDefenderTamper = new Regex(
            @"(?:Add-MpPreference|Set-MpPreference|MpCmdRun)\s+.{0,300}?(?:-ExclusionPath|-ExclusionProcess|-ExclusionExtension|-DisableRealtimeMonitoring\s+(?:\$true|1)|-DisableBehaviorMonitoring\s+(?:\$true|1)|-DisableIOAVProtection\s+(?:\$true|1)|-DisableScriptScanning)|(?:reg(?:\.exe)?\s+add|Set-ItemProperty).{0,300}?(?:DisableAntiSpyware|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableOnAccessProtection|ms-settings\\Shell\\Open\\command)|DisableAntiSpyware\s*(?:=|:|/d)\s*""?1|netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off|wevtutil(?:\.exe)?\s+cl\s+(?:Security|System|Application)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase, RxTimeout);
        static readonly Regex RxHtmlSmuggling = new Regex(
            @"(?:(?:new\s+)?Blob\s*\(.{0,300}?(?:atob|Uint8Array|fromCharCode)|atob\s*\(\s*['""][A-Za-z0-9+/=]{24,}|URL\.createObjectURL|msSaveOrOpenBlob|ActiveXObject\s*\(\s*['""](?:WScript\.Shell|ADODB\.Stream)|TVqQAAMAAAAEAAAA|<svg[^>]{0,200}onload\s*=|WebAssembly\.instantiate)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline, RxTimeout);
        static readonly Regex RxLolBinStager = new Regex(
            @"(?:certutil(?:\.exe)?\s+[^\r\n]{0,200}?(?:-urlcache|-decode|-decodehex)|mshta(?:\.exe)?\s+(?:https?://|vbscript:|javascript:)|regsvr32(?:\.exe)?\s+[^\r\n]{0,200}?(?:/i:https?://|scrobj\.dll)|rundll32(?:\.exe)?\s+(?:javascript:|shell32\.dll,Control_RunDLL)|bitsadmin(?:\.exe)?\s+/transfer|(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\r\n]{0,250}?\|[^\r\n]{0,120}?(?:iex|Invoke-Expression)|Invoke-WebRequest\s+[^\r\n]{0,200}?-OutFile|Start-BitsTransfer|wmic(?:\.exe)?\s+process\s+call\s+create|wmic(?:\.exe)?\s+[^\r\n]{0,160}?/format\s*:\s*[""']?https?://|certreq(?:\.exe)?\s+-Post|msiexec(?:\.exe)?\s+/q\w*\s+/i\s+https?://|forfiles(?:\.exe)?\s+[^\r\n]{0,200}?/c\s+[""'].{0,180}?(?:cmd|powershell|mshta)|cmstp(?:\.exe)?\s+/s|odbcconf(?:\.exe)?\s+[^\r\n]{0,160}?REGSVR|navigator\.clipboard\.writeText\s*\(.{0,220}?(?:powershell|mshta|cmd)|CodeTaskFactory|UsingTask.{0,180}?AssemblyFile)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline, RxTimeout);
        static readonly Regex RxMemoryShield = new Regex(
            @"(?:comsvcs\.dll\s*,?\s*MiniDump|MiniDumpWriteDump.{0,220}?lsass|\\Device\\PhysicalMemory|NtMapViewOfSection.{0,300}?NtQueueApcThread|HellsGate|HalosGate|TartarusGate|SysWhispers|Marshal\.Copy.{0,250}?CallWindowProc)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline, RxTimeout);
        static readonly Regex RxRatPersistence = new Regex(
            @"(?:schtasks(?:\.exe)?\s+/create\s+[^\r\n]{0,240}?(?:/sc\s+(?:onlogon|onstart|minute)|powershell|pwsh|cmd\.exe|wscript|mshta|appdata|programdata)|CurrentVersion\\Run(?:Once)?[^\r\n]{0,240}?\\(?:Temp|AppData|Public)|Image File Execution Options\\.{0,220}?""?Debugger""?\s*=|SilentProcessExit\\.{0,220}?""?MonitorProcess""?\s*=|sc(?:\.exe)?\s+create\s+[^\r\n]{0,180}?type=\s*kernel)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline, RxTimeout);
        static readonly Regex RxStealerExfil = new Regex(
            @"(?:(?:Login Data|Local State|cookies\.sqlite|nkbihfbeogaeaoehlefnkodbefgpgknn|Exodus|Electrum).{0,400}?(?:CryptUnprotectData|webhook|api\.telegram\.org|HttpClient|WebClient|TcpClient)|(?:discord\.com/api/webhooks/|api\.telegram\.org/bot|transfer\.sh).{0,400}?(?:Screenshot|Keylog|GetAsyncKeyState|CopyFromScreen|Password|Wallet|Token))",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline, RxTimeout);
        static readonly Regex RxShadowWipe = new Regex(
            @"(?:vssadmin(?:\.exe)?\s+delete\s+shadows|wmic(?:\.exe)?\s+shadowcopy\s+delete|wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup)|bcdedit(?:\.exe)?\s+.{0,140}?recoveryenabled\s+no)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline, RxTimeout);
        static readonly Regex RxWmiFileless = new Regex(
            @"(?:Invoke-CimMethod|Invoke-WmiMethod).{0,200}?Win32_Process.{0,120}?Create|CommandLineEventConsumer|__FilterToConsumerBinding",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline, RxTimeout);
        static readonly Regex RxElectronDiscord = new Regex(
            @"(?:discord_desktop_core|app\.asar|BrowserWindow).{0,450}?(?:webRequest\.onBeforeRequest|discord\.com/api/webhooks/|api/v\d+/users/@me|mfa\.[A-Za-z0-9_-]{10,}|Authorization)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline, RxTimeout);
        static readonly Regex RxLazarusStealer = new Regex(
            @"(?:solana[/\\]id\.json|Local Extension Settings|Phantom|MetaMask|BraveSoftware.{0,140}?Login Data).{0,500}?(?:child_process|subprocess\.Popen|urllib\.request|requests\.post|fetch\s*\(|http\.request)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline, RxTimeout);
        static readonly Regex RxWebClickFix = new Regex(
            @"(?:(?:navigator\.clipboard\.writeText|document\.execCommand\s*\(\s*['""]copy['""]\)).{0,400}?(?:powershell|pwsh|mshta|cmd(?:\.exe)?|curl\s+|iex\b|irm\b|https?://)|(?:Win\s*\+\s*R|Windows\s*\+\s*R).{0,300}?(?:Ctrl\s*\+\s*V|powershell|mshta|cmd))",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline, RxTimeout);
        static readonly Regex RxWebCryptojacker = new Regex(
            @"(?:CoinHive\.Anonymous|CryptoLoot\.Anonymous|deepMiner|webminerpool|stratum\+tcp://|moneroocean|cryptonight\s*wasm|xmrig)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline, RxTimeout);
        static readonly Regex RxWebSkimmer = new Regex(
            @"(?:(?:cardnumber|cc_number|credit_?card|billing_card|card_?cvv|cvv2).{0,400}?(?:sendBeacon|XMLHttpRequest|fetch\s*\(|new\s+Image\s*\(|btoa\s*\(|discord\.com/api/webhooks|api\.telegram\.org)|(?:eval|Function)\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\()",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline, RxTimeout);
        static readonly Regex RxClipBanker = new Regex(
            @"(?:(?:GetText|Clipboard\.Get|AddClipboardFormatListener|GetClipboardData).{0,400}?(?:SetText|Clipboard\.Set|SetClipboardData).{0,400}?(?:bc1[qpzry9x8gf2tvdw0s]|0x[a-fA-F0-9]{40}|T[A-Za-z1-9]{33}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}|wallet|btc|eth|xmr|usdt)|(?:AddClipboardFormatListener|SetClipboardData).{0,350}?(?:bc1|TRC20|ERC20|Monero|Exodus))",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline, RxTimeout);
        static readonly Regex RxHiddenVnc = new Regex(
            @"CreateDesktop[AW]?\s*.{0,400}?(?:SetThreadDesktop|OpenDesktop|SwitchDesktop|BitBlt|PrintWindow)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline, RxTimeout);
        static readonly Regex RxReverseShell = new Regex(
            @"(?:(?:System\.Net\.Sockets\.TcpClient|New-Object\s+Net\.Sockets\.TcpClient).{0,400}?(?:GetStream|StreamReader|StreamWriter|cmd\.exe|powershell|RedirectStandardInput)|(?:socket\.socket\s*\(|net\.createConnection\s*\(|net\.Socket\s*\().{0,400}?(?:subprocess|pty\.spawn|child_process|cmd\.exe|powershell|dup2))",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline, RxTimeout);
        static readonly Regex RxSecurityKiller = new Regex(
            @"(?:(?:DisableTaskMgr|DisableRegistryTools|DisableCMD)\s*(?:=|:|/d)\s*[""']?1|(?:net(?:\.exe)?\s+stop|sc(?:\.exe)?\s+(?:stop|config|delete))\s+(?:WinDefend|WdNisSvc|Sense|SecurityHealthService|MpsSvc)|MpCmdRun(?:\.exe)?\s+.{0,120}?-RemoveDefinitions|taskkill(?:\.exe)?\s+/f\s+/im\s+(?:MsMpEng|MpDefenderCoreService|AegisScanner|Taskmgr|ProcessHacker|procexp))",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline, RxTimeout);
        static readonly Regex RxMultiAppStealer = new Regex(
            @"(?:key4\.db|logins\.json|PK11SDR_Decrypt|tdata[/\\]D877F783D5D3EF8C|IElevator|VaultEnumerateItems|FileZilla[/\\](?:recentservers|sitemanager)\.xml).{0,400}?(?:webhook|api\.telegram\.org|HttpClient|WebClient|MultipartFormData|requests\.post|fetch\s*\(|urllib|TcpClient|ZipArchive|CreateFromDirectory|CryptUnprotectData|NSS_Init)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline, RxTimeout);
        static readonly Regex RxComAutoRunHijack = new Regex(
            @"(?:Software\\Classes\\CLSID\\\{[0-9a-fA-F-]{36}\}\\(?:InprocServer32|LocalServer32|TreatAs)|Software\\Microsoft\\Command Processor[^\r\n]{0,160}?AutoRun|Windows NT\\CurrentVersion\\Windows[^\r\n]{0,160}?AppInit_DLLs|Control\\Lsa[^\r\n]{0,160}?(?:Security Packages|Notification Packages))",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline, RxTimeout);

        static MalwareDb LoadDb(string dbPath)
        {
            MalwareDb db;
            if (File.Exists(dbPath))
            {
                var fi = new FileInfo(dbPath);
                if (fi.Length > 32 * 1024 * 1024)
                {
                    db = new MalwareDb();
                    db.BuildIndexes();
                    return db;
                }
                string json = File.ReadAllText(dbPath, Encoding.UTF8);
                db = JsonSerializer.Deserialize<MalwareDb>(json) ?? new MalwareDb();
            }
            else
            {
                db = new MalwareDb();
            }
            db.BuildIndexes();
            return db;
        }

        static double CalculateEntropy(ReadOnlySpan<byte> data)
        {
            int length = data.Length;
            if (length == 0) return 0.0;
            Span<int> counts = stackalloc int[256];
            for (int i = 0; i < length; i++)
            {
                counts[data[i]]++;
            }
            double entropy = 0.0;
            double invLen = 1.0 / length;
            for (int i = 0; i < 256; i++)
            {
                int c = counts[i];
                if (c > 0)
                {
                    double p = c * invLen;
                    entropy -= p * Math.Log2(p);
                }
            }
            return Math.Round(entropy, 3);
        }

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminAcquireContext(out IntPtr phCatAdmin, IntPtr pgSubsystem, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile, ref int pcbHash, byte[] pbHash, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, int cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

        private static readonly ThreadLocal<IntPtr> s_catAdmin = new(() =>
        {
            CryptCATAdminAcquireContext(out IntPtr h, IntPtr.Zero, 0);
            return h;
        });

        static bool IsCatalogSigned(string filePath)
        {
            IntPtr hCatAdmin = s_catAdmin.Value;
            if (hCatAdmin == IntPtr.Zero) return false;
            IntPtr hCatInfo = IntPtr.Zero;
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                IntPtr handle = fs.SafeFileHandle.DangerousGetHandle();
                int hashLen = 0;
                CryptCATAdminCalcHashFromFileHandle(handle, ref hashLen, Array.Empty<byte>(), 0);
                if (hashLen <= 0) return false;

                byte[] hash = new byte[hashLen];
                if (!CryptCATAdminCalcHashFromFileHandle(handle, ref hashLen, hash, 0))
                    return false;

                IntPtr prev = IntPtr.Zero;
                hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashLen, 0, ref prev);
                return hCatInfo != IntPtr.Zero;
            }
            catch
            {
                return false;
            }
            finally
            {
                if (hCatInfo != IntPtr.Zero)
                    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

        static bool VerifyAuthenticodeChainTrust(string filePath)
        {
            var actionGuid = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = filePath,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };
            IntPtr pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            bool structMarshaled = false;
            try
            {
                Marshal.StructureToPtr(fileInfo, pFileInfo, false);
                structMarshaled = true;
                var wvtData = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                    dwUIChoice = 2,          // WTD_UI_NONE
                    fdwRevocationChecks = 1, // WTD_REVOKE_WHOLECHAIN (cached CRL check)
                    dwUnionChoice = 1,       // WTD_CHOICE_FILE
                    pFile = pFileInfo,
                    dwStateAction = 1,       // WTD_STATEACTION_VERIFY
                    dwProvFlags = 0x00000080 // WTD_CACHE_ONLY_URL_RETRIEVAL
                };
                int status = WinVerifyTrust(IntPtr.Zero, ref actionGuid, ref wvtData);
                wvtData.dwStateAction = 2; // WTD_STATEACTION_CLOSE
                WinVerifyTrust(IntPtr.Zero, ref actionGuid, ref wvtData);
                return status == 0;
            }
            catch
            {
                return false;
            }
            finally
            {
                if (structMarshaled)
                    Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFileInfo);
                Marshal.FreeHGlobal(pFileInfo);
            }
        }

        static readonly ConcurrentDictionary<string, (bool IsSigned, string Signer, bool HasUntrustedCert)> s_authCache =
            new(StringComparer.OrdinalIgnoreCase);

        static string BuildAuthCacheKey(string filePath)
        {
            try
            {
                var fi = new FileInfo(filePath);
                if (fi.Exists)
                    return $"{filePath}|{fi.Length}|{fi.LastWriteTimeUtc.Ticks}|{fi.CreationTimeUtc.Ticks}";
            }
            catch { }
            return filePath;
        }

        static (string Downloads, string Desktop, string Startup) ResolveSpecialFolders()
        {
            string downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            string startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);

            if (OperatingSystem.IsWindows())
            {
                try
                {
                    using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders");
                    if (key != null)
                    {
                        static string ReadRegFolder(Microsoft.Win32.RegistryKey k, string valueName, string fallback)
                        {
                            var raw = k.GetValue(valueName) as string;
                            if (string.IsNullOrWhiteSpace(raw)) return fallback;
                            var exp = Environment.ExpandEnvironmentVariables(raw).Trim();
                            return Directory.Exists(exp) ? exp : fallback;
                        }
                        downloads = ReadRegFolder(key, "{374DE290-123F-4565-9164-39C4925E467B}", downloads);
                        desktop = ReadRegFolder(key, "Desktop", desktop);
                        startup = ReadRegFolder(key, "Startup", startup);
                    }
                }
                catch { }
            }
            return (downloads, desktop, startup);
        }

        static string ResolveOsEditionLabel()
        {
            string fallback = $"{RuntimeInformation.OSDescription} ({RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant()})";
            if (!OperatingSystem.IsWindows()) return fallback;
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                if (key != null)
                {
                    string productName = (key.GetValue("ProductName") as string ?? "Windows").Trim();
                    if (productName.StartsWith("Microsoft ", StringComparison.OrdinalIgnoreCase))
                        productName = productName.Substring(10);
                    string buildStr = (key.GetValue("CurrentBuildNumber") as string ?? "0").Trim();
                    if (int.TryParse(buildStr, out int buildNum) && buildNum >= 22000 && productName.Contains("Windows 10", StringComparison.OrdinalIgnoreCase))
                    {
                        productName = productName.Replace("Windows 10", "Windows 11", StringComparison.OrdinalIgnoreCase);
                    }
                    string arch = Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit";
                    return $"{productName} {arch}";
                }
            }
            catch { }
            return fallback;
        }

        [DllImport("kernel32.dll")]
        private static extern uint GetLogicalDrives();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetProcessWorkingSetSize(IntPtr hProcess, nint dwMinimumWorkingSetSize, nint dwMaximumWorkingSetSize);

        static void TrimWorkingSet()
        {
            try
            {
                GC.Collect(2, GCCollectionMode.Optimized, blocking: false);
                if (OperatingSystem.IsWindows())
                {
                    using var cur = Process.GetCurrentProcess();
                    SetProcessWorkingSetSize(cur.Handle, -1, -1);
                }
            }
            catch { }
        }

        private static uint s_lastDriveMask = uint.MaxValue;
        private static List<object> s_cachedRemovableDrives = new();
        private static readonly object s_driveCacheLock = new();

        static List<object> GetRemovableDriveInfos()
        {
            uint mask = OperatingSystem.IsWindows() ? GetLogicalDrives() : 0;
            lock (s_driveCacheLock)
            {
                if (mask != 0 && mask == s_lastDriveMask)
                    return s_cachedRemovableDrives;

                var drives = new List<object>();
                foreach (var d in DriveInfo.GetDrives())
                {
                    try
                    {
                        if (d.IsReady && d.DriveType == DriveType.Removable)
                        {
                            drives.Add(new { root = d.RootDirectory.FullName, label = string.IsNullOrWhiteSpace(d.VolumeLabel) ? "USB Disk" : d.VolumeLabel });
                        }
                    }
                    catch { }
                }
                s_lastDriveMask = mask;
                s_cachedRemovableDrives = drives;
                return drives;
            }
        }

        static (bool IsSigned, string Signer, bool HasUntrustedCert) CheckAuthenticode(string filePath, bool knownPe = false)
        {
            string cacheKey = BuildAuthCacheKey(filePath);
            if (s_authCache.TryGetValue(cacheKey, out var cachedAuth))
                return cachedAuth;
            if (s_authCache.Count > 2048)
                s_authCache.Clear();

            bool hasUntrustedCert = false;
            (bool, string, bool) result = (false, "", false);
            try
            {
                if (!knownPe)
                {
                    var ext = Path.GetExtension(filePath).ToLowerInvariant();
                    if (ext != ".exe" && ext != ".dll" && ext != ".sys" && ext != ".msi" && ext != ".drv" && ext != ".cpl" && ext != ".ocx")
                        return result;
                }

                // 1. Embedded Authenticode certificate check + cryptographic WinVerifyTrust chain validation first (avoids double-hashing large third-party EXEs!)
                bool embeddedPresent = false;
                string cn = "Verified Publisher";
                try
                {
                    #pragma warning disable SYSLIB0057
                    var cert = X509Certificate.CreateFromSignedFile(filePath);
                    #pragma warning restore SYSLIB0057
                    if (cert != null)
                    {
                        embeddedPresent = true;
                        string subject = cert.Subject ?? "";
                        int cnIdx = subject.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);
                        if (cnIdx >= 0)
                        {
                            int end = subject.IndexOf(',', cnIdx);
                            cn = (end > cnIdx ? subject.Substring(cnIdx + 3, end - cnIdx - 3) : subject.Substring(cnIdx + 3)).Trim('"');
                        }
                    }
                }
                catch { }

                if (embeddedPresent)
                {
                    if (VerifyAuthenticodeChainTrust(filePath))
                    {
                        result = (true, cn, false);
                        s_authCache[cacheKey] = result;
                        return result;
                    }
                    hasUntrustedCert = true;
                }

                // 2. Fall back to Windows Security Catalog verification (handles inbox Microsoft System32 catalog-signed binaries)
                if (IsCatalogSigned(filePath))
                {
                    result = (true, "Microsoft Windows Catalog", false);
                    s_authCache[cacheKey] = result;
                    return result;
                }
            }
            catch
            {
                if (IsCatalogSigned(filePath))
                {
                    result = (true, "Microsoft Windows Catalog", false);
                    s_authCache[cacheKey] = result;
                    return result;
                }
            }

            result = (false, "", hasUntrustedCert);
            s_authCache[cacheKey] = result;
            return result;
        }

        static bool InspectPeCertTablePadding(string filePath, byte[] buffer, int bufferLength, uint certFileOff, uint certSize)
        {
            if (certFileOff == 0 || certSize <= 256) return false;
            try
            {
                int readLen = (int)Math.Min(certSize, 2U * 1024U * 1024U);
                byte[] certData;
                if (certFileOff + readLen <= bufferLength)
                {
                    certData = new byte[readLen];
                    Buffer.BlockCopy(buffer, (int)certFileOff, certData, 0, readLen);
                }
                else
                {
                    using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    if (certFileOff >= fs.Length) return false;
                    fs.Seek(certFileOff, SeekOrigin.Begin);
                    certData = new byte[readLen];
                    int n = fs.Read(certData, 0, readLen);
                    if (n < 16) return false;
                    if (n < readLen) Array.Resize(ref certData, n);
                }

                if (certData.Length < 16 || certData[8] != 0x30) return false;
                byte b1 = certData[9];
                int derLen;
                if (b1 < 0x80)
                {
                    derLen = 2 + b1;
                }
                else
                {
                    int nb = b1 & 0x7F;
                    if (nb == 0 || nb > 4 || 10 + nb > certData.Length) return false;
                    int contentLen = 0;
                    for (int idx = 0; idx < nb; idx++) contentLen = (contentLen << 8) | certData[10 + idx];
                    derLen = 2 + nb + contentLen;
                }

                int padStart = 8 + derLen;
                if ((long)certSize <= padStart + 256) return false;

                byte[] trailing;
                if (certSize > certData.Length)
                {
                    int extraLen = (int)Math.Min(2L * 1024L * 1024L, (long)certSize - padStart);
                    trailing = new byte[extraLen];
                    using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    fs.Seek((long)certFileOff + padStart, SeekOrigin.Begin);
                    int r = fs.Read(trailing, 0, extraLen);
                    if (r < extraLen) Array.Resize(ref trailing, r);
                }
                else
                {
                    int tLen = (int)certSize - padStart;
                    if (tLen <= 256 || padStart + tLen > certData.Length) return false;
                    trailing = new byte[tLen];
                    Buffer.BlockCopy(certData, padStart, trailing, 0, tLen);
                }

                var nonZero = new List<byte>(Math.Min(trailing.Length, 65536));
                for (int i = 0; i < trailing.Length; i++)
                {
                    if (trailing[i] != 0) nonZero.Add(trailing[i]);
                }
                if (nonZero.Count <= 64) return false;

                var nzSpan = CollectionsMarshal.AsSpan(nonZero);
                string nzText = Encoding.ASCII.GetString(nzSpan);
                if (nzText.Contains("MZ") && nzText.Contains("PE\0\0")) return true;
                string nzLower = nzText.ToLowerInvariant();
                if (nzLower.Contains("http://") || nzLower.Contains("https://") || nzLower.Contains("powershell")
                    || nzLower.Contains("<script") || nzLower.Contains("wscript") || nzLower.Contains("invoke-")
                    || nzLower.Contains("frombase64") || nzLower.Contains("cmd.exe"))
                    return true;
                if (Regex.IsMatch(nzText, @"[A-Za-z0-9+/]{36,}={0,2}", RegexOptions.None, RxTimeout))
                    return true;
                if (nonZero.Count > 1024 && CalculateEntropy(nzSpan.Slice(0, Math.Min(nzSpan.Length, 65536))) > 5.8)
                    return true;
            }
            catch { }
            return false;
        }

        static (bool IsDotNet, bool HasCertPaddingTrojan, bool BinaryPumping) InspectPeStructure(string filePath, long fileSize, byte[] buffer, int bufferLength, ScanResultItem item)
        {
            if (bufferLength < 64 || buffer[0] != 0x4D || buffer[1] != 0x5A) return (false, false, false);
            item.IsPe = true;
            bool isDotNet = false;
            bool hasCertPaddingTrojan = false;
            bool binaryPumping = false;

            try
            {
                int peOffset = BitConverter.ToInt32(buffer, 0x3C);
                if (peOffset < 0 || peOffset + 24 > bufferLength) return (false, false, false);
                if (buffer[peOffset] != 0x50 || buffer[peOffset + 1] != 0x45 || buffer[peOffset + 2] != 0 || buffer[peOffset + 3] != 0)
                    return (false, false, false);

                ushort numSections = BitConverter.ToUInt16(buffer, peOffset + 6);
                ushort optSize = BitConverter.ToUInt16(buffer, peOffset + 20);
                int optOff = peOffset + 24;
                int secTableOffset = optOff + optSize;
                if (optOff + 20 > bufferLength) return (false, false, false);

                ushort optMagic = BitConverter.ToUInt16(buffer, optOff);
                bool isPe64 = optMagic == 0x20B;
                uint entryPointRva = BitConverter.ToUInt32(buffer, optOff + 16);

                // Check DataDirectory[1] (Import Table), DataDirectory[4] (Security Cert Table), DataDirectory[9] (TLS), DataDirectory[14] (CLR)
                int ddBase = optOff + (isPe64 ? 112 : 96);
                uint importRva = 0, importSize = 0, certFileOff = 0, certSize = 0, tlsRva = 0, tlsSize = 0, clrRva = 0, clrSize = 0;
                if (ddBase + 80 <= optOff + optSize && ddBase + 80 <= bufferLength)
                {
                    importRva = BitConverter.ToUInt32(buffer, ddBase + 8);
                    importSize = BitConverter.ToUInt32(buffer, ddBase + 12);
                    certFileOff = BitConverter.ToUInt32(buffer, ddBase + 4 * 8);
                    certSize = BitConverter.ToUInt32(buffer, ddBase + 4 * 8 + 4);
                    tlsRva = BitConverter.ToUInt32(buffer, ddBase + 9 * 8);
                    tlsSize = BitConverter.ToUInt32(buffer, ddBase + 9 * 8 + 4);
                }
                if (ddBase + 120 <= optOff + optSize && ddBase + 120 <= bufferLength)
                {
                    clrRva = BitConverter.ToUInt32(buffer, ddBase + 14 * 8);
                    clrSize = BitConverter.ToUInt32(buffer, ddBase + 14 * 8 + 4);
                    isDotNet = (clrRva > 0 && clrSize >= 72);
                }

                if (certFileOff > 0 && certSize > 256 && InspectPeCertTablePadding(filePath, buffer, bufferLength, certFileOff, certSize))
                {
                    hasCertPaddingTrojan = true;
                    item.RiskScore = Math.Min(100, item.RiskScore + 96);
                    item.Reasons.Add("[SuperLX 1.0 İmza Bütünlüğü] CVE-2013-3900: İmzalı PE sertifika tablosu sonuna gizlenmiş trojan yükü");
                    if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "Trojan.PE.CertTablePaddingCVE2013_3900";
                }

                bool entryInText = false;
                bool hasCodeSection = false;
                string epSectionName = "";
                string[] packerNames = { "UPX", ".vmp", ".themida", ".enigma", ".aspack", ".nsp", ".petite", ".mpress", ".rlpack" };
                long maxPeEnd = secTableOffset + Math.Min((int)numSections, 32) * 40L;

                for (int i = 0; i < Math.Min((int)numSections, 24); i++)
                {
                    int secOff = secTableOffset + (i * 40);
                    if (secOff + 40 > bufferLength) break;

                    string secName = Encoding.ASCII.GetString(buffer, secOff, 8).TrimEnd('\0');
                    uint virtSize = BitConverter.ToUInt32(buffer, secOff + 8);
                    uint virtAddr = BitConverter.ToUInt32(buffer, secOff + 12);
                    uint rawSize = BitConverter.ToUInt32(buffer, secOff + 16);
                    uint rawPtr = BitConverter.ToUInt32(buffer, secOff + 20);
                    uint characteristics = BitConverter.ToUInt32(buffer, secOff + 36);

                    long secEnd = (long)rawPtr + rawSize;
                    if (secEnd > maxPeEnd) maxPeEnd = secEnd;

                    if (secName.Equals(".text", StringComparison.OrdinalIgnoreCase) || secName.Equals("CODE", StringComparison.OrdinalIgnoreCase))
                        hasCodeSection = true;

                    uint span = Math.Max(virtSize, rawSize);
                    if (entryPointRva > 0 && entryPointRva >= virtAddr && entryPointRva < virtAddr + span)
                    {
                        epSectionName = secName;
                        if (secName.Equals(".text", StringComparison.OrdinalIgnoreCase) || secName.Equals("CODE", StringComparison.OrdinalIgnoreCase))
                            entryInText = true;
                    }

                    // IMAGE_SCN_MEM_WRITE (0x80000000) & IMAGE_SCN_MEM_EXECUTE (0x20000000)
                    bool isWrite = (characteristics & 0x80000000) != 0;
                    bool isExec = (characteristics & 0x20000000) != 0;
                    if (isWrite && isExec)
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 35);
                        item.Reasons.Add($"[SuperLX 1.0 PE Bellek] Yazılabilir+Çalıştırılabilir (RWX) PE bölümü: {secName}");
                    }

                    // High-entropy executable/data section (packed shellcode stub)
                    if (rawPtr < bufferLength && rawSize > 2048 && !secName.Equals(".rsrc", StringComparison.OrdinalIgnoreCase))
                    {
                        int sampleLen = (int)Math.Min(rawSize, (uint)(bufferLength - rawPtr));
                        if (sampleLen > 2048)
                        {
                            double secEnt = CalculateEntropy(buffer.AsSpan((int)rawPtr, Math.Min(sampleLen, 262144)));
                            if (secEnt > 7.45)
                            {
                                item.RiskScore = Math.Min(100, item.RiskScore + 30);
                                item.Reasons.Add($"[SuperLX 1.0 Entropi] Yüksek entropili PE bölümü: {secName} ({secEnt}/8.0)");
                            }
                        }
                    }

                    if (packerNames.Any(p => secName.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 40);
                        item.Reasons.Add($"[SuperLX 1.0 PE Packer] Şifreli/Sıkıştırılmış PE bölümü tespit edildi: {secName}");
                    }
                }

                if (certFileOff > 0 && (long)certFileOff + certSize > maxPeEnd)
                    maxPeEnd = (long)certFileOff + certSize;

                // Binary Pumping overlay detection (>= 5 MB overlay with low-entropy padding)
                long overlaySize = fileSize - maxPeEnd;
                if (maxPeEnd > 0 && overlaySize >= 5L * 1024L * 1024L && File.Exists(filePath))
                {
                    try
                    {
                        using var pfs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        byte[] probe = new byte[65536];
                        double entSum = 0;
                        int entCount = 0;
                        foreach (long pos in new[] { maxPeEnd, maxPeEnd + overlaySize / 2, Math.Max(maxPeEnd, fileSize - 65536) })
                        {
                            pfs.Seek(pos, SeekOrigin.Begin);
                            int pr = pfs.Read(probe, 0, probe.Length);
                            if (pr > 0)
                            {
                                entSum += CalculateEntropy(probe.AsSpan(0, pr));
                                entCount++;
                            }
                        }
                        if (entCount > 0 && (entSum / entCount) < 1.2)
                        {
                            binaryPumping = true;
                            item.RiskScore = Math.Min(100, item.RiskScore + 55);
                            item.Reasons.Add($"[SuperLX 1.0 PE Şişirme] Boyut atlatma amacıyla aşırı düşük entropili dev overlay dolgusu ({Math.Round(overlaySize / (1024.0 * 1024.0), 1)} MB)");
                            if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "Evasion.Trojan.BinaryPumping";
                        }
                    }
                    catch { }
                }

                if (hasCodeSection && entryPointRva > 0 && !entryInText && !string.IsNullOrEmpty(epSectionName))
                {
                    item.RiskScore = Math.Min(100, item.RiskScore + 30);
                    item.Reasons.Add($"[SuperLX 1.0 PE Anomali] Giriş noktası (OEP) standart .text dışında: {epSectionName}");
                }
                if (importRva == 0 && importSize == 0 && entryPointRva > 0 && !isDotNet)
                {
                    item.RiskScore = Math.Min(100, item.RiskScore + 30);
                    item.Reasons.Add("[SuperLX 1.0 PE IAT] Boş İçe Aktarma Tablosu (API Hashing / Shellcode Loader şüphesi)");
                }
                if (tlsRva > 0 && tlsSize > 0)
                {
                    item.RiskScore = Math.Min(100, item.RiskScore + 10);
                    item.Reasons.Add("[SuperLX 1.0 PE TLS] TLS Callback tablosu (Erken Anti-Debug / Stealth yükleme)");
                }

                // Direct & Indirect Syscall / Hell's Gate stub detection
                int syscallStubs = 0;
                for (int k = 0; k < bufferLength - 12; k++)
                {
                    if (buffer[k] == 0x4C && buffer[k + 1] == 0x8B && buffer[k + 2] == 0xD1 && buffer[k + 3] == 0xB8)
                    {
                        bool upperZero = k + 7 < bufferLength && buffer[k + 6] == 0x00 && buffer[k + 7] == 0x00;
                        for (int s = 8; s <= 18 && k + s + 2 < bufferLength; s++)
                        {
                            bool direct = buffer[k + s] == 0x0F && buffer[k + s + 1] == 0x05 && buffer[k + s + 2] == 0xC3;
                            bool indirect = upperZero && (
                                (buffer[k + s] == 0xFF && buffer[k + s + 1] == 0x25) ||
                                (buffer[k + s] == 0x41 && buffer[k + s + 1] == 0xFF && buffer[k + s + 2] >= 0xE0 && buffer[k + s + 2] <= 0xE7) ||
                                (buffer[k + s] == 0xFF && buffer[k + s + 1] >= 0xE0 && buffer[k + s + 1] <= 0xE7)
                            );
                            if (direct || indirect)
                            {
                                syscallStubs++;
                                break;
                            }
                        }
                        if (syscallStubs >= 3) break;
                    }
                }
                if (syscallStubs >= 3)
                {
                    item.RiskScore = Math.Min(100, item.RiskScore + 55);
                    item.Reasons.Add("[SuperLX 1.0 Çekirdek Koruması] Doğrudan/Dolaylı Windows Syscall / SysWhispers EDR atlatma stub imzası");
                }
            }
            catch { }
            return (isDotNet, hasCertPaddingTrojan, binaryPumping);
        }

        static ScanResultItem AnalyzeSingleFile(string filePath, MalwareDb db, bool fastAuthenticode = true)
        {
            var item = new ScanResultItem
            {
                Path = filePath,
                FileName = Path.GetFileName(filePath),
                Engine = ActiveEngineName
            };

            byte[]? buffer = null;
            byte[]? tailBuffer = null;
            byte[]? streamChunk = null;

            try
            {
                var fi = new FileInfo(filePath);
                if (!fi.Exists) return item;
                item.SizeBytes = fi.Length;

                // 0. Unicode RTLO / Bidi Spoofing filename check (e.g. invoice_gpj.exe masquerading as image)
                foreach (char ch in item.FileName)
                {
                    if (ch == '\u202E' || ch == '\u202D' || ch == '\u202A' || ch == '\u202B' || (ch >= '\u2066' && ch <= '\u2069'))
                    {
                        item.RiskScore = 95;
                        item.ThreatName = "Trojan.Masquerade.UnicodeRTLO";
                        item.Reasons.Add("[SuperLX 1.0 İsim Kalkanı] Sahte dosya uzantısı göstermek için Unicode RTLO yön değiştirme karakteri kullanılmış");
                        break;
                    }
                }

                int tierCap = fastAuthenticode ? 512 * 1024 : 2 * 1024 * 1024;
                int maxRead = (int)Math.Min(fi.Length, tierCap);
                buffer = maxRead > 0 ? ArrayPool<byte>.Shared.Rent(maxRead) : Array.Empty<byte>();
                int bytesRead = 0;
                int tailBytesRead = 0;

                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    if (maxRead > 0)
                    {
                        bytesRead = fs.Read(buffer, 0, maxRead);
                    }

                    // Full-file SHA-256 up to 250 MB in deep single-file mode (50 MB in fast bulk scan)
                    long maxHashLen = fastAuthenticode ? 50L * 1024 * 1024 : 250L * 1024 * 1024;
                    if (fi.Length <= maxRead)
                    {
                        item.Sha256 = Convert.ToHexString(SHA256.HashData(buffer.AsSpan(0, bytesRead))).ToLowerInvariant();
                    }
                    else if (fi.Length <= maxHashLen)
                    {
                        using var inc = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                        inc.AppendData(buffer, 0, bytesRead);
                        streamChunk = ArrayPool<byte>.Shared.Rent(131072);
                        int r;
                        while ((r = fs.Read(streamChunk, 0, 131072)) > 0)
                            inc.AppendData(streamChunk, 0, r);
                        item.Sha256 = Convert.ToHexString(inc.GetHashAndReset()).ToLowerInvariant();
                    }
                    else
                    {
                        item.Sha256 = Convert.ToHexString(SHA256.HashData(buffer.AsSpan(0, bytesRead))).ToLowerInvariant();
                    }

                    // Capture trailing 512 KB overlay for large files in deep single-file mode
                    if (!fastAuthenticode && fi.Length > maxRead + 1024)
                    {
                        int tailLen = (int)Math.Min(524288L, fi.Length - maxRead);
                        tailBuffer = ArrayPool<byte>.Shared.Rent(tailLen);
                        fs.Seek(-tailLen, SeekOrigin.End);
                        tailBytesRead = fs.Read(tailBuffer, 0, tailLen);
                    }
                }

                // 1. PE Header Check
                bool hasCertPaddingTrojan = false;
                bool hasBinaryPumping = false;
                if (bytesRead >= 2 && buffer[0] == 0x4D && buffer[1] == 0x5A)
                {
                    (_, hasCertPaddingTrojan, hasBinaryPumping) = InspectPeStructure(filePath, fi.Length, buffer, bytesRead, item);
                }

                // 3. Calculate Shannon Entropy
                item.Entropy = CalculateEntropy(buffer.AsSpan(0, bytesRead));

                // [AŞAMA 1] Bilinen Virüs SHA-256 + Bilinen Zararlı DLL / BYOVD + DLL Side-Loading Kontrolü
                string lowerFullPath = filePath.ToLowerInvariant();
                if (db.ByovdDriverSet.Contains(item.FileName))
                {
                    item.Status = "INFECTED";
                    item.ThreatName = $"Rootkit.BYOVD.VulnerableDriver.{item.FileName}";
                    item.Severity = "CRITICAL";
                    item.RiskScore = 95;
                    item.DetectionStage = "Aşama 1: BYOVD Zafiyetli Sürücü Kalkanı";
                    item.Reasons.Add($"[Aşama 1 - BYOVD] İmzalı olsa dahi EDR/AV körleştirmede kullanılan zafiyetli sürücü: {item.FileName}");
                    return item;
                }
                if (db.MaliciousDllSet.Contains(item.FileName))
                {
                    item.Status = "INFECTED";
                    item.ThreatName = $"Trojan.KnownMaliciousDLL.{item.FileName}";
                    item.Severity = "CRITICAL";
                    item.RiskScore = 100;
                    item.DetectionStage = "Aşama 1: Bilinen Zararlı DLL Veritabanı";
                    item.Reasons.Add($"[Aşama 1 - Zararlı DLL] Tehdit veritabanındaki bilinen kötü amaçlı DLL: {item.FileName}");
                    return item;
                }

                if (db.HijackableDllSet.Contains(item.FileName))
                {
                    bool inTrustedWin = lowerFullPath.StartsWith("c:\\windows\\system32\\") || lowerFullPath.StartsWith("c:\\windows\\syswow64\\") || lowerFullPath.StartsWith("c:\\windows\\winsxs\\");
                    bool inSuspiciousUserDir = lowerFullPath.Contains("\\appdata\\") || lowerFullPath.Contains("\\temp\\") || lowerFullPath.Contains("\\downloads\\") || lowerFullPath.Contains("\\users\\public\\") || lowerFullPath.Contains("\\desktop\\") || lowerFullPath.Contains("\\programdata\\") || lowerFullPath.Contains("\\documents\\") || lowerFullPath.Contains("\\onedrive\\");
                    if (!inTrustedWin && inSuspiciousUserDir)
                    {
                        var (dllSigned, _, _) = CheckAuthenticode(filePath, true);
                        if (!dllSigned)
                        {
                            item.Status = "INFECTED";
                            item.ThreatName = $"Trojan.DLLSideLoading.{item.FileName}";
                            item.Severity = "CRITICAL";
                            item.RiskScore = 95;
                            item.DetectionStage = "Aşama 1: Zararlı DLL Side-Loading Tespiti";
                            item.Reasons.Add($"[Aşama 1 - DLL Hijacking] Sistem DLL adı ({item.FileName}) System32 dışında imzasız olarak konumlandırılmış");
                            return item;
                        }
                    }
                }

                // 4. Exact SHA-256 Signature Check
                if (db.Sha256Signatures.TryGetValue(item.Sha256, out var sig) && sig.Severity != "SAFE")
                {
                    item.Status = "INFECTED";
                    item.ThreatName = sig.Name;
                    item.Severity = sig.Severity;
                    item.RiskScore = 100;
                    item.DetectionStage = "Aşama 1: SHA-256 Virüs İmza Veritabanı";
                    item.Reasons.Add($"[Aşama 1 - SHA-256 İmza Eşleşmesi] {sig.Description} ({sig.Name})");
                    return item;
                }

                // 5. Magic-Byte Spoofing & High-Risk Unsigned XLL Check (SuperLX 1.0)
                string ext = Path.GetExtension(item.FileName).ToLowerInvariant();
                string[] safeMediaDocExts = { ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".txt", ".doc", ".docx", ".xls", ".xlsx" };
                if (item.IsPe && safeMediaDocExts.Contains(ext))
                {
                    item.RiskScore = Math.Min(100, item.RiskScore + 92);
                    item.Reasons.Add($"[SuperLX 1.0 Magic-Byte] {ext} uzantılı görünümlü çalıştırılabilir Windows PE (MZ) dosyası");
                    if (string.IsNullOrEmpty(item.ThreatName))
                        item.ThreatName = "Trojan.SpoofedExtension.Executable";
                }
                else if (item.IsPe && ext == ".xll")
                {
                    item.RiskScore = Math.Min(100, item.RiskScore + 88);
                    item.Reasons.Add("[SuperLX 1.0 XLL Kalkanı] İmzasız Excel (.xll) yerel PE eklentisi");
                    if (string.IsNullOrEmpty(item.ThreatName))
                        item.ThreatName = "Trojan.Office.UnsignedXLLAddIn";
                }

                // 5B. SuperLX 1.0 Polyglot & Archive Stream Embedded PE Check
                string[] polyglotExts = { ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".cab", ".tar", ".iso", ".img" };
                if (!item.IsPe && polyglotExts.Contains(ext))
                {
                    int sliceCount = (tailBuffer != null && tailBytesRead > 24) ? 2 : 1;
                    for (int sliceIdx = 0; sliceIdx < sliceCount; sliceIdx++)
                    {
                        ReadOnlySpan<byte> slice = sliceIdx == 0
                            ? buffer.AsSpan(0, bytesRead)
                            : tailBuffer!.AsSpan(0, tailBytesRead);
                        if (slice.Length <= 24) continue;
                        bool detectedPoly = false;
                        for (int i = 4; i < slice.Length - 8; i++)
                        {
                            if (slice[i] == 0x4D && slice[i + 1] == 0x5A)
                            {
                                int peLimit = Math.Min(slice.Length - 4, i + 512);
                                bool foundPeSig = false;
                                for (int j = i + 2; j < peLimit; j++)
                                {
                                    if (slice[j] == 0x50 && slice[j + 1] == 0x45 && slice[j + 2] == 0x00 && slice[j + 3] == 0x00)
                                    {
                                        foundPeSig = true;
                                        break;
                                    }
                                }
                                if (foundPeSig)
                                {
                                    item.RiskScore = Math.Min(100, item.RiskScore + 92);
                                    item.Reasons.Add($"[SuperLX 1.0 Polyglot] {ext} dosyası arkasında gizlenmiş Windows PE yükü (offset {i})");
                                    if (string.IsNullOrEmpty(item.ThreatName))
                                        item.ThreatName = "Trojan.Polyglot.EmbeddedPE";
                                    detectedPoly = true;
                                    break;
                                }
                            }
                        }
                        if (detectedPoly) break;
                    }
                }

                // 5C. Weaponized LNK Shortcut Detector
                if (ext == ".lnk" && bytesRead > 16)
                {
                    string lnkAllText = Encoding.ASCII.GetString(buffer, 0, bytesRead) + "\n" + Encoding.Unicode.GetString(buffer, 0, bytesRead);
                    if (RxLnkWeaponized.IsMatch(lnkAllText))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 92);
                        item.Reasons.Add("[SuperLX 1.0 LNK Kalkanı] Kısayol (.lnk) hedefinde gizlenmiş uzaktan kod çalıştırma komutu");
                        if (string.IsNullOrEmpty(item.ThreatName))
                            item.ThreatName = "Trojan.LNK.WeaponizedShortcut";
                    }
                }

                // 6. Fast Byte (UTF-8 + lazy UTF-16LE up to 2 MB) / Behavioral Pattern Scanning + Kill-Chain Tracking
                string utf8Content = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                bool hasNullByte = bytesRead <= 2 * 1024 * 1024 && buffer.AsSpan(0, Math.Min(bytesRead, 4096)).IndexOf((byte)0) >= 0;
                string utf16Content = hasNullByte ? Encoding.Unicode.GetString(buffer, 0, bytesRead) : "";
                if (tailBuffer != null && tailBytesRead > 0)
                {
                    utf8Content += "\n" + Encoding.UTF8.GetString(tailBuffer, 0, tailBytesRead);
                }
                var matchedCategories = new HashSet<string>();
                int injectionHitCount = 0;

                // 5D. SuperLX 1.0 Managed .NET RAT Crypter / Assembly.Load Detector
                bool hasAssemblyLoad = (utf8Content.Contains("Assembly", StringComparison.Ordinal) || utf8Content.Contains("AppDomain", StringComparison.Ordinal) || utf8Content.Contains("GetDelegateForFunctionPointer", StringComparison.Ordinal) || (!string.IsNullOrEmpty(utf16Content) && (utf16Content.Contains("Assembly", StringComparison.Ordinal) || utf16Content.Contains("AppDomain", StringComparison.Ordinal)))) &&
                    (utf8Content.Contains("FromBase64String", StringComparison.OrdinalIgnoreCase) || utf8Content.Contains("GetManifestResourceStream", StringComparison.Ordinal) || utf8Content.Contains("GetPixel", StringComparison.Ordinal) || (!string.IsNullOrEmpty(utf16Content) && (utf16Content.Contains("FromBase64String", StringComparison.OrdinalIgnoreCase) || utf16Content.Contains("GetManifestResourceStream", StringComparison.Ordinal) || utf16Content.Contains("GetPixel", StringComparison.Ordinal))));
                bool hasNetCrypto = utf8Content.Contains("RijndaelManaged", StringComparison.Ordinal) ||
                    utf8Content.Contains("AesCryptoServiceProvider", StringComparison.Ordinal) ||
                    utf8Content.Contains("AesManaged", StringComparison.Ordinal) ||
                    utf8Content.Contains("Aes.Create", StringComparison.Ordinal) ||
                    utf8Content.Contains("TripleDES", StringComparison.Ordinal) ||
                    utf8Content.Contains("ResourceManager", StringComparison.Ordinal) ||
                    utf8Content.Contains("LockBits", StringComparison.Ordinal) ||
                    utf8Content.Contains("GZipStream", StringComparison.Ordinal) ||
                    utf8Content.Contains("DeflateStream", StringComparison.Ordinal) ||
                    (!string.IsNullOrEmpty(utf16Content) && (utf16Content.Contains("RijndaelManaged", StringComparison.Ordinal) || utf16Content.Contains("Aes.Create", StringComparison.Ordinal) || utf16Content.Contains("ResourceManager", StringComparison.Ordinal)));
                bool hasInvoke = utf8Content.Contains("MethodInfo", StringComparison.Ordinal) ||
                    utf8Content.Contains("DynamicInvoke", StringComparison.Ordinal) ||
                    utf8Content.Contains("CallByName", StringComparison.Ordinal) ||
                    utf8Content.Contains("EntryPoint.Invoke", StringComparison.OrdinalIgnoreCase) ||
                    (!string.IsNullOrEmpty(utf16Content) && (utf16Content.Contains("EntryPoint.Invoke", StringComparison.OrdinalIgnoreCase) || utf16Content.Contains("MethodInfo", StringComparison.Ordinal) || utf16Content.Contains("DynamicInvoke", StringComparison.Ordinal)));
                if (hasAssemblyLoad && hasNetCrypto && hasInvoke)
                {
                    item.RiskScore = Math.Min(100, item.RiskScore + 85);
                    item.Reasons.Add("[SuperLX 1.0 .NET Crypter] Bellek içi dinamik şifreli/steganografik yük çözücü (Assembly.Load + Crypto/Stego)");
                    if (string.IsNullOrEmpty(item.ThreatName))
                        item.ThreatName = "RAT.MSIL.EncryptedReflectiveLoader";
                }

                // 5E. SuperLX 1.0 Native C# Defender Blind-Spot & Stealth Persistence Signatures
                if (!item.IsPe)
                {
                    string corpusForRegex = utf16Content.Length > 32 && utf16Content.Contains("powershell", StringComparison.OrdinalIgnoreCase)
                        ? utf8Content + "\n" + utf16Content
                        : utf8Content;

                    if (RxDefenderTamper.IsMatch(corpusForRegex))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 95);
                        item.Reasons.Add("[SuperLX 1.0] Windows Defender/Firewall/UAC/Olay Günlüğü körleştirme (Tamper) girişimi");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "DefenseEvasion.DefenderTamper.ExclusionAbuse";
                    }
                    if ((ext == ".html" || ext == ".htm" || ext == ".hta" || ext == ".svg" || ext == ".sct" || ext == ".wsf") && RxHtmlSmuggling.IsMatch(corpusForRegex))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 90);
                        item.Reasons.Add("[SuperLX 1.0 HTML/SVG Smuggling] Tarayıcı veya WSH belleğinde gizli çalıştırılabilir yük oluşturma");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "Trojan.HTMLSmuggling.Dropper";
                    }
                    if ((ext == ".html" || ext == ".htm" || ext == ".js" || ext == ".mjs" || ext == ".svg" || ext == ".hta") && RxWebClickFix.IsMatch(corpusForRegex))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 96);
                        item.Reasons.Add("[SuperLX 1.0 Web Virüs Kalkanı] ClickFix / Sahte CAPTCHA pano enjeksiyon saldırısı");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "Web.ClickFix.ClipboardSocialEng";
                    }
                    if ((ext == ".html" || ext == ".htm" || ext == ".js" || ext == ".mjs" || ext == ".wasm") && RxWebCryptojacker.IsMatch(corpusForRegex))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 88);
                        item.Reasons.Add("[SuperLX 1.0 Web Virüs Kalkanı] Tarayıcı içi gizli kripto madenci (Cryptojacker)");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "Web.Cryptojacker.WasmMiner";
                    }
                    if ((ext == ".html" || ext == ".htm" || ext == ".js" || ext == ".mjs") && RxWebSkimmer.IsMatch(corpusForRegex))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 90);
                        item.Reasons.Add("[SuperLX 1.0 Web Virüs Kalkanı] Web Skimmer / Gizlenmiş zararlı JavaScript yürütücüsü");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "Web.Skimmer.ObfuscatedJS";
                    }
                    if (RxLolBinStager.IsMatch(corpusForRegex))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 88);
                        item.Reasons.Add("[SuperLX 1.0 LOLBin] Windows yerleşik aracıyla dosyasız zararlı yük indirme zinciri");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "Execution.LOLBin.FilelessStager";
                    }
                    if (RxMemoryShield.IsMatch(corpusForRegex))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 95);
                        item.Reasons.Add("[SuperLX 1.0 Bellek Kalkanı] LSASS bellek dökümü / Early-Bird APC / Syscall Evasion kalıbı");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "CredentialAccess.LSASS_BYOVD.MemoryDump";
                    }
                    if (RxRatPersistence.IsMatch(corpusForRegex))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 82);
                        item.Reasons.Add("[SuperLX 1.0 RAT Kalıcılık] Görev zamanlayıcı, Registry Run veya IFEO kalıcılık kancası");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "RAT.Persistence.ScheduledTask";
                    }
                    if (RxStealerExfil.IsMatch(corpusForRegex))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 92);
                        item.Reasons.Add("[SuperLX 1.0 Anti-Stealer] Tarayıcı/Kripto cüzdan hırsızlığı ve dışa sızdırma korelasyonu");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "Stealer.Behavioral.BrowserCryptoExfil";
                    }
                    if (RxShadowWipe.IsMatch(corpusForRegex))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 98);
                        item.Reasons.Add("[SuperLX 1.0 Fidye Kalkanı] Gölge kopya / Sistem kurtarma silme komutu");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "Ransomware.ShadowCopy.RecoveryWipe";
                    }
                    if (RxWmiFileless.IsMatch(corpusForRegex))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 90);
                        item.Reasons.Add("[SuperLX 1.0 WMI/CIM] Dosyasız Win32_Process veya WMI kalıcılık yürütmesi");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "Execution.WMI_CIM.FilelessExec";
                    }
                    if (RxElectronDiscord.IsMatch(corpusForRegex))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 94);
                        item.Reasons.Add("[SuperLX 1.0 İstemci Enjeksiyonu] Electron / Discord desktop_core token hırsızlığı enjeksiyonu");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "Trojan.Stealer.ElectronDiscordInject";
                    }
                    if (RxLazarusStealer.IsMatch(corpusForRegex))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 95);
                        item.Reasons.Add("[SuperLX 1.0 APT Kalkanı] Lazarus / BeaverTail tarzı kripto cüzdan & kimlik bilgisi sızdırma zinciri");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "APT.Lazarus.SupplyChainStealer";
                    }
                    if (RxClipBanker.IsMatch(corpusForRegex))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 90);
                        item.Reasons.Add("[SuperLX 1.0 ClipBanker] Pano izleme ve kripto cüzdan adresi değiştirme truva atı");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "Trojan.ClipBanker.CryptoHijacker";
                    }
                    if (RxHiddenVnc.IsMatch(corpusForRegex))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 88);
                        item.Reasons.Add("[SuperLX 1.0 HVNC] Gizli masaüstü (Hidden VNC) oluşturma ve kontrol API zinciri");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "Trojan.RAT.HiddenVNC";
                    }
                    if (RxReverseShell.IsMatch(corpusForRegex))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 90);
                        item.Reasons.Add("[SuperLX 1.0 Backdoor] Etkileşimli ters kabuk (Reverse Shell) TCP soket bağlantısı");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "Trojan.Backdoor.ReverseShell";
                    }
                    if (RxSecurityKiller.IsMatch(corpusForRegex))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 94);
                        item.Reasons.Add("[SuperLX 1.0 Sabotaj Kalkanı] Defender / Güvenlik servisi veya Görev Yöneticisi devre dışı bırakma saldırısı");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "Trojan.DefenseEvasion.SecurityKiller";
                    }
                    if (RxMultiAppStealer.IsMatch(corpusForRegex))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 93);
                        item.Reasons.Add("[SuperLX 1.0 Anti-Stealer] Çoklu uygulama (Firefox/Telegram/Chrome/FileZilla) kimlik hırsızlığı ve sızdırma");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "Trojan.Stealer.MultiAppHarvest";
                    }
                    if (RxComAutoRunHijack.IsMatch(corpusForRegex))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 88);
                        item.Reasons.Add("[SuperLX 1.0 Kalıcılık] COM CLSID, AutoRun veya AppInit_DLLs kalıcılık gaspı");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "Trojan.Persistence.COMOrAutoRunHijack";
                    }
                    if (ext == ".pdf" && Regex.IsMatch(utf8Content, @"/OpenAction|/Launch\s|/(?:JS|JavaScript)\s", RegexOptions.IgnoreCase) &&
                        Regex.IsMatch(utf8Content, @"powershell|cmd\.exe|mshta|wscript|certutil|http://|https://", RegexOptions.IgnoreCase))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 88);
                        item.Reasons.Add("[SuperLX 1.0 PDF Kalkanı] PDF içinde otomatik açılan (/OpenAction /Launch) zararlı komut");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "Exploit.PDF.WeaponizedAction";
                    }
                    if ((ext == ".iqy" || ext == ".slk" || ext == ".csv") && Regex.IsMatch(utf8Content, @"=\s*(?:cmd|powershell|mshta|wscript)\s*[|!]", RegexOptions.IgnoreCase))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 90);
                        item.Reasons.Add("[SuperLX 1.0 DDE Kalkanı] Excel/Office belgesinde zararlı DDE komut çalıştırma enjeksiyonu");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "Trojan.Office.DDEInjection";
                    }
                    if ((ext == ".url" || ext == ".scf") && Regex.IsMatch(utf8Content, @"(?:IconFile|URL)\s*=\s*(?:file://)?\\\\(?!(?:127\.0\.0\.1|localhost)\\)[A-Za-z0-9_.-]+\\", RegexOptions.IgnoreCase))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 86);
                        item.Reasons.Add("[SuperLX 1.0 Ağ Kalkanı] Dış SMB/UNC yoluyla NTLM kimlik bilgisi sızdırma bağlantısı");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "CredentialAccess.SMB.NTLMHashLeak";
                    }
                    if (ext == ".reg" && RxRatPersistence.IsMatch(utf8Content))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 88);
                        item.Reasons.Add("[SuperLX 1.0 Kayıt Kalkanı] .reg ile IFEO Debugger veya başlangıç kalıcılığı enjeksiyonu");
                        if (string.IsNullOrEmpty(item.ThreatName)) item.ThreatName = "DefenseEvasion.Registry.MaliciousImport";
                    }
                }

                foreach (var pat in db.BytePatterns)
                {
                    if (utf8Content.Contains(pat.Pattern, StringComparison.OrdinalIgnoreCase) ||
                        (!string.IsNullOrEmpty(utf16Content) && utf16Content.Contains(pat.Pattern, StringComparison.OrdinalIgnoreCase)))
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + pat.Score);
                        item.Reasons.Add($"[{pat.Id}] {pat.Description}");
                        if (!string.IsNullOrEmpty(pat.Category))
                        {
                            matchedCategories.Add(pat.Category);
                            if (pat.Category == "ProcessInjection" || pat.Category == "ProcessHollowing")
                                injectionHitCount++;
                        }

                        if (string.IsNullOrEmpty(item.ThreatName))
                            item.ThreatName = pat.Name;
                        if (pat.Severity == "CRITICAL")
                            item.Severity = "CRITICAL";
                        else if (pat.Severity == "HIGH" && item.Severity != "CRITICAL")
                            item.Severity = "HIGH";
                    }
                }

                // Kill-Chain Multi-Condition & Anti-RAT Behavioral Correlation
                if (injectionHitCount >= 2)
                {
                    item.RiskScore = Math.Min(100, item.RiskScore + 30);
                    item.Reasons.Add("[SuperLX 1.0 Davranış Korelasyonu] Çoklu Bellek Enjeksiyonu / Hollowing (Kill-Chain) API zinciri tespit edildi");
                }
                if (matchedCategories.Contains("DefenseEvasion") && (matchedCategories.Contains("ProcessInjection") || matchedCategories.Contains("CredentialAccess")))
                {
                    item.RiskScore = Math.Min(100, item.RiskScore + 35);
                    item.Reasons.Add("[SuperLX 1.0 EDR Korelasyonu] Güvenlik atlatma (AMSI/ETW) + saldırı tekniği kombinasyonu");
                }
                if (matchedCategories.Contains("Spyware") && (matchedCategories.Contains("Backdoor") || matchedCategories.Contains("Exfiltration") || matchedCategories.Contains("CredentialAccess")))
                {
                    item.RiskScore = Math.Min(100, item.RiskScore + 45);
                    item.Reasons.Add("[SuperLX 1.0 Anti-RAT Kill-Chain] Casus izleme (Keylogger/Ekran/Kamera) + C2 sızdırma zinciri korelasyonu");
                    if (string.IsNullOrEmpty(item.ThreatName) || item.ThreatName.StartsWith("Backdoor."))
                        item.ThreatName = "RAT.Behavioral.SpywareKillChain";
                }

                // 7. Double Extension Heuristic
                string lowerName = item.FileName.ToLowerInvariant();
                string[] docExts = { ".pdf.", ".doc.", ".docx.", ".xls.", ".xlsx.", ".jpg.", ".png.", ".txt." };
                if (db.SuspiciousExtSet.Contains(ext))
                {
                    foreach (var dExt in docExts)
                    {
                        if (lowerName.Contains(dExt))
                        {
                            item.RiskScore = Math.Min(100, item.RiskScore + 65);
                            item.Reasons.Add($"[SuperLX 1.0 Çift Uzantı] Sahte belge uzantısı ile gizlenmiş çalıştırılabilir dosya ({item.FileName})");
                            if (string.IsNullOrEmpty(item.ThreatName))
                                item.ThreatName = "Heuristic.Trojan.DoubleExtension";
                            break;
                        }
                    }
                }

                // 8. Check genuine Windows Authenticode Chain Trust when needed
                if (item.IsPe && (!fastAuthenticode || item.RiskScore >= 35 || item.Entropy > 7.65))
                {
                    var (isSigned, signer, hasUntrustedCert) = CheckAuthenticode(filePath, true);
                    item.IsSigned = isSigned;
                    item.Signer = signer;
                    if (hasUntrustedCert && !isSigned)
                    {
                        item.RiskScore = Math.Min(100, item.RiskScore + 45);
                        item.Reasons.Add("[SuperLX 1.0 İmza Güvenliği] Güvenilmeyen (Self-Signed) veya bozulmuş Authenticode sertifikası tespit edildi");
                        if (string.IsNullOrEmpty(item.ThreatName))
                            item.ThreatName = "Heuristic.UntrustedSignature.SpoofedPE";
                    }
                }

                // 9. Unsigned + High Entropy Packed PE Check
                if (item.IsPe && item.Entropy > 7.65 && !item.IsSigned)
                {
                    item.RiskScore = Math.Min(100, item.RiskScore + 45);
                    item.Reasons.Add($"[Sezgisel: Yüksek Entropi ({item.Entropy}/8.0)] İmzasız paketlenmiş/şifrelenmiş PE yürütülebilir dosya");
                    if (string.IsNullOrEmpty(item.ThreatName))
                        item.ThreatName = "Heuristic.Packed.UnsignedPE";
                }

                // 10. Trusted Digital Signature Policy: Verified Authenticode/Catalog binaries with no exact malware hash, BYOVD, or cert-padding tamper are legitimate
                bool hasExactHashMatch = db.Sha256Signatures.TryGetValue(item.Sha256, out var exactSig) && exactSig.Severity != "SAFE";
                bool isByovdOrTamper = hasCertPaddingTrojan || hasBinaryPumping || db.ByovdDriverSet.Contains(item.FileName);
                if (item.IsSigned && !hasExactHashMatch && !isByovdOrTamper)
                {
                    item.RiskScore = 0;
                    item.Reasons.Clear();
                    item.ThreatName = "";
                    item.Severity = "SAFE";
                    item.DetectionStage = "Temiz (Güvenilir İmza + Aşama 1-3 Geçildi)";
                }

                // Finalize status
                if (item.RiskScore >= 70)
                {
                    item.Status = "INFECTED";
                    if (item.Severity == "SAFE") item.Severity = "CRITICAL";
                    if (!item.DetectionStage.StartsWith("Aşama 1"))
                    {
                        bool isSuperLx = item.Reasons.Any(r => r.Contains("SuperLX 1.0"));
                        bool hasStage2 = item.Reasons.Any(r => r.Contains("Entropi") || r.Contains("Çift Uzantı") || r.Contains("PE") || r.Contains("Polyglot") || r.Contains("LNK"));
                        item.DetectionStage = isSuperLx
                            ? "SuperLX 1.0 Kör Nokta Motoru"
                            : hasStage2
                                ? $"{ActiveEngineName} · Aşama 2 Yapısal & Sezgisel"
                                : $"{ActiveEngineName} · Aşama 3 Davranışsal Korelasyon";
                    }
                }
                else if (item.RiskScore >= 35)
                {
                    item.Status = "SUSPICIOUS";
                    if (item.Severity == "SAFE") item.Severity = "MEDIUM";
                    if (!item.DetectionStage.StartsWith("Aşama 1"))
                    {
                        bool isSuperLx = item.Reasons.Any(r => r.Contains("SuperLX 1.0"));
                        bool hasStage2 = item.Reasons.Any(r => r.Contains("Entropi") || r.Contains("Çift Uzantı") || r.Contains("PE") || r.Contains("Polyglot") || r.Contains("LNK"));
                        item.DetectionStage = isSuperLx
                            ? "SuperLX 1.0 Kör Nokta Motoru"
                            : hasStage2
                                ? $"{ActiveEngineName} · Aşama 2 Yapısal & Sezgisel"
                                : $"{ActiveEngineName} · Aşama 3 Davranışsal Korelasyon";
                    }
                }
                else if (!item.IsSigned)
                {
                    item.DetectionStage = $"Temiz ({ActiveEngineName} Geçildi)";
                }
            }
            catch (Exception)
            {
                // Ignore locked system files
            }
            finally
            {
                if (buffer != null && buffer.Length > 0)
                    ArrayPool<byte>.Shared.Return(buffer);
                if (tailBuffer != null && tailBuffer.Length > 0)
                    ArrayPool<byte>.Shared.Return(tailBuffer);
                if (streamChunk != null && streamChunk.Length > 0)
                    ArrayPool<byte>.Shared.Return(streamChunk);
            }

            return item;
        }

        static List<string> CollectFiles(string targetPath, int maxFiles = 10000, int recursionDepth = 5, string aegisRoot = "")
        {
            var files = new List<string>();
            if (File.Exists(targetPath))
            {
                files.Add(targetPath);
                return files;
            }
            if (!Directory.Exists(targetPath)) return files;

            bool hasAegisRoot = !string.IsNullOrEmpty(aegisRoot);
            try
            {
                var enumOptions = new EnumerationOptions
                {
                    IgnoreInaccessible = true,
                    RecurseSubdirectories = true,
                    MaxRecursionDepth = recursionDepth
                };
                files.AddRange(Directory.EnumerateFiles(targetPath, "*", enumOptions)
                    .Where(f =>
                    {
                        if (f.Contains("\\node_modules\\", StringComparison.OrdinalIgnoreCase)
                            || f.Contains("\\.git\\", StringComparison.OrdinalIgnoreCase)
                            || f.Contains("\\$Recycle.Bin", StringComparison.OrdinalIgnoreCase)
                            || f.Contains("\\System Volume Information", StringComparison.OrdinalIgnoreCase)
                            || f.Contains("\\WinSxS\\", StringComparison.OrdinalIgnoreCase)
                            || f.Contains("!_00_aegis_")
                            || f.Contains("~_zz_aegis_"))
                        {
                            return false;
                        }
                        if (hasAegisRoot && f.StartsWith(aegisRoot, StringComparison.OrdinalIgnoreCase))
                        {
                            if (f.Contains("\\quarantine\\", StringComparison.OrdinalIgnoreCase)
                                || f.Contains("\\signatures\\", StringComparison.OrdinalIgnoreCase)
                                || f.Contains("\\engines\\", StringComparison.OrdinalIgnoreCase)
                                || f.Contains("\\vortex\\", StringComparison.OrdinalIgnoreCase)
                                || f.Contains("\\AEGIS_Vault\\", StringComparison.OrdinalIgnoreCase)
                                || f.Contains("\\AEGIS_Shadow", StringComparison.OrdinalIgnoreCase)
                                || f.EndsWith("\\server.js", StringComparison.OrdinalIgnoreCase)
                                || f.Contains("\\bin\\", StringComparison.OrdinalIgnoreCase)
                                || f.Contains("\\obj\\", StringComparison.OrdinalIgnoreCase))
                            {
                                return false;
                            }
                        }
                        return true;
                    })
                    .Take(maxFiles));
            }
            catch { }
            return files;
        }

        static void RunScan(List<(string Path, int Limit, int Depth)> targetPaths, string labelTarget, string dbPath, bool streamProgress = false, int maxTotalFiles = 22000)
        {
            var sw = Stopwatch.StartNew();
            var db = LoadDb(dbPath);
            var summary = new ScanSummary { Target = labelTarget, Engine = ActiveEngineName };

            string aegisRoot = "";
            try
            {
                string sigDir = Path.GetDirectoryName(Path.GetFullPath(dbPath)) ?? "";
                aegisRoot = Directory.GetParent(sigDir)?.FullName ?? "";
            }
            catch { }

            var filesToScan = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in targetPaths)
            {
                if (filesToScan.Count >= maxTotalFiles) break;
                foreach (var f in CollectFiles(entry.Path, entry.Limit, entry.Depth, aegisRoot))
                {
                    filesToScan.Add(f);
                    if (filesToScan.Count >= maxTotalFiles) break;
                }
            }

            int totalCount = filesToScan.Count;
            int scannedCounter = 0;
            int totalScanned = 0;
            var detections = new ConcurrentBag<ScanResultItem>();
            var topScanned = new List<ScanResultItem>(128);
            object topLock = new object();
            long totalBytes = 0;
            object consoleLock = new object();
            int maxPar = Math.Max(2, Math.Min(Environment.ProcessorCount, 6));

            Parallel.ForEach(filesToScan, new ParallelOptions { MaxDegreeOfParallelism = maxPar }, file =>
            {
                var res = AnalyzeSingleFile(file, db, true);
                Interlocked.Add(ref totalBytes, res.SizeBytes);
                Interlocked.Increment(ref totalScanned);
                if (res.Status == "INFECTED" || res.Status == "SUSPICIOUS")
                {
                    detections.Add(res);
                }

                lock (topLock)
                {
                    if (topScanned.Count < 120)
                    {
                        topScanned.Add(res);
                    }
                    else
                    {
                        int minIdx = 0;
                        var minItem = topScanned[0];
                        for (int i = 1; i < topScanned.Count; i++)
                        {
                            var cur = topScanned[i];
                            if (cur.RiskScore < minItem.RiskScore || (cur.RiskScore == minItem.RiskScore && cur.Entropy < minItem.Entropy))
                            {
                                minItem = cur;
                                minIdx = i;
                            }
                        }
                        if (res.RiskScore > minItem.RiskScore || (res.RiskScore == minItem.RiskScore && res.Entropy > minItem.Entropy))
                        {
                            topScanned[minIdx] = res;
                        }
                    }
                }

                int current = Interlocked.Increment(ref scannedCounter);
                if (streamProgress && (current % 180 == 0 || current == totalCount))
                {
                    lock (consoleLock)
                    {
                        Console.WriteLine($"PROGRESS|{current}|{totalCount}|{file}");
                    }
                }
            });

            sw.Stop();
            summary.TotalFilesScanned = totalScanned;
            summary.TotalBytesScanned = totalBytes;
            summary.DurationMs = Math.Max(1, sw.ElapsedMilliseconds);
            summary.FilesPerSecond = Math.Round((double)summary.TotalFilesScanned / (summary.DurationMs / 1000.0), 1);
            summary.Detections = detections.OrderByDescending(d => d.RiskScore).ToList();
            summary.ThreatsFound = summary.Detections.Count(d => d.Status == "INFECTED");
            summary.SuspiciousFound = summary.Detections.Count(d => d.Status == "SUSPICIOUS");
            summary.ScannedFiles = topScanned.OrderByDescending(f => f.RiskScore).ThenByDescending(f => f.Entropy).ToList();

            Console.OutputEncoding = Encoding.UTF8;
            string json = JsonSerializer.Serialize(summary);
            Console.WriteLine(streamProgress ? $"RESULT|{json}" : json);
        }

        static void RunQuickScan(string dbPath, string extraZone, bool streamProgress = false)
        {
            var targets = new List<(string Path, int Limit, int Depth)>();
            if (!string.IsNullOrEmpty(extraZone) && Directory.Exists(extraZone))
                targets.Add((extraZone, 2000, 4));

            var (resolvedDownloads, resolvedDesktop, resolvedStartup) = ResolveSpecialFolders();
            string startup = !string.IsNullOrEmpty(resolvedStartup) ? resolvedStartup : Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            if (!string.IsNullOrEmpty(startup) && Directory.Exists(startup))
                targets.Add((startup, 1000, 3));

            string downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            if (!string.IsNullOrEmpty(resolvedDownloads) && Directory.Exists(resolvedDownloads))
                targets.Add((resolvedDownloads, 2500, 4));
            if (Directory.Exists(downloads) && !downloads.Equals(resolvedDownloads, StringComparison.OrdinalIgnoreCase))
                targets.Add((downloads, 2500, 4));
            if (!string.IsNullOrEmpty(resolvedDesktop) && Directory.Exists(resolvedDesktop))
                targets.Add((resolvedDesktop, 1500, 3));

            string tempPath = Path.GetTempPath();
            if (Directory.Exists(tempPath))
                targets.Add((tempPath, 3500, 3));

            string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
            if (Directory.Exists(system32))
                targets.Add((system32, 9500, 3));

            string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            if (Directory.Exists(programData))
                targets.Add((programData, 3500, 4));

            RunScan(targets, "Sistem Geneli Kritik Alanlar (System32, ProgramData, Startup, Downloads, Temp)", dbPath, streamProgress);
        }

        static void RunFullScan(string dbPath, string extraZone, bool streamProgress = false)
        {
            var targets = new List<(string Path, int Limit, int Depth)>();
            if (!string.IsNullOrEmpty(extraZone) && Directory.Exists(extraZone))
                targets.Add((extraZone, 3000, 5));

            var (resolvedDownloads, resolvedDesktop, _) = ResolveSpecialFolders();
            string downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            if (!string.IsNullOrEmpty(resolvedDownloads) && Directory.Exists(resolvedDownloads)) targets.Add((resolvedDownloads, 3000, 5));
            if (Directory.Exists(downloads) && !downloads.Equals(resolvedDownloads, StringComparison.OrdinalIgnoreCase)) targets.Add((downloads, 3000, 5));

            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            if (!string.IsNullOrEmpty(resolvedDesktop) && Directory.Exists(resolvedDesktop)) targets.Add((resolvedDesktop, 2000, 4));
            if (Directory.Exists(desktop) && !desktop.Equals(resolvedDesktop, StringComparison.OrdinalIgnoreCase)) targets.Add((desktop, 2000, 4));

            string docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            if (Directory.Exists(docs)) targets.Add((docs, 2000, 4));

            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            if (Directory.Exists(appData)) targets.Add((appData, 3000, 4));

            string progData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            if (Directory.Exists(progData)) targets.Add((progData, 3000, 4));

            string progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            if (Directory.Exists(progFiles)) targets.Add((progFiles, 4000, 3));

            string progFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            if (Directory.Exists(progFilesX86)) targets.Add((progFilesX86, 4000, 3));

            string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
            if (Directory.Exists(system32)) targets.Add((system32, 6000, 2));

            foreach (var drive in DriveInfo.GetDrives())
            {
                try
                {
                    if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                    {
                        targets.Add((drive.RootDirectory.FullName, 2000, 2));
                    }
                }
                catch { }
            }

            RunScan(targets, "Tam Sistem Taraması (Tüm Sabit Diskler, Kullanıcı Profilleri, Programlar ve Windows)", dbPath, streamProgress, 26000);
        }

        static readonly HashSet<string> s_lolbinNetNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "powershell", "pwsh", "mshta", "wscript", "cscript", "rundll32", "regsvr32",
            "certutil", "bitsadmin", "msiexec", "regasm", "regsvcs", "installutil",
            "msbuild", "forfiles", "cmstp", "odbcconf", "hh", "pcalua", "certreq", "wmic", "finger"
        };

        static readonly string[] s_trustedAppDataVendors =
        {
            "\\microsoft\\", "\\programs\\microsoft vs code\\", "\\programs\\python\\",
            "\\discord\\", "\\telegram desktop\\", "\\google\\", "\\bravesoftware\\",
            "\\opera", "\\jetbrains\\", "\\slack\\", "\\zoom\\", "\\spotify\\",
            "\\githubdesktop\\", "\\antigravity\\", "\\steam\\", "\\mozilla\\", "\\vivaldi\\"
        };

        static readonly HashSet<string> s_selfTrustedBins = BuildSelfTrustedBins();

        static HashSet<string> BuildSelfTrustedBins()
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                string binDir = Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\');
                set.Add(Path.Combine(binDir, "aegisscanner.exe").ToLowerInvariant());
                string rootDir = Path.GetFullPath(Path.Combine(binDir, "..", "..", "..")).TrimEnd('\\');
                set.Add(Path.Combine(rootDir, "aegiscore.exe").ToLowerInvariant());
                set.Add(Path.Combine(rootDir, "runtime", "node", "node.exe").ToLowerInvariant());
                set.Add(Path.Combine(rootDir, "runtime", "python", "python.exe").ToLowerInvariant());
            }
            catch { }
            return set;
        }

        static (bool HighRiskDrop, bool UnsignedAppDataNonVendor) ClassifyProcessDropPath(string lowerPath)
        {
            if (string.IsNullOrEmpty(lowerPath)) return (false, false);
            if (s_selfTrustedBins.Contains(lowerPath)) return (false, false);
            bool highRiskDrop = lowerPath.Contains("\\appdata\\local\\temp\\")
                || lowerPath.Contains("\\users\\public\\")
                || lowerPath.Contains("\\downloads\\")
                || lowerPath.Contains("\\desktop\\")
                || lowerPath.Contains("\\programdata\\")
                || lowerPath.Contains("\\windows\\temp\\")
                || lowerPath.Contains("\\windows\\tasks\\");
            bool inAppData = lowerPath.Contains("\\appdata\\roaming\\") || lowerPath.Contains("\\appdata\\local\\");
            bool trustedVendor = inAppData && s_trustedAppDataVendors.Any(v => lowerPath.Contains(v));
            bool unsignedAppDataNonVendor = inAppData && !highRiskDrop && !trustedVendor;
            return (highRiskDrop, unsignedAppDataNonVendor);
        }

        static ProcessNetReport BuildProcessesAndNetworkReport(MalwareDb db)
        {
            var report = new ProcessNetReport();

            var procs = Process.GetProcesses();
            report.TotalProcesses = procs.Length;
            var procBag = new ConcurrentBag<ProcessItem>();
            var pidNameMap = new ConcurrentDictionary<int, string>();

            int procMaxPar = Math.Max(2, Math.Min(4, Environment.ProcessorCount));
            Parallel.ForEach(procs, new ParallelOptions { MaxDegreeOfParallelism = procMaxPar }, p =>
            {
                try
                {
                    pidNameMap[p.Id] = p.ProcessName;
                    var item = new ProcessItem
                    {
                        Pid = p.Id,
                        Name = p.ProcessName,
                        MemoryMb = Math.Round(p.WorkingSet64 / (1024.0 * 1024.0), 2),
                        Threads = p.Threads.Count
                    };

                    try
                    {
                        item.Path = p.MainModule?.FileName ?? "";
                    }
                    catch
                    {
                        item.Path = "Sistem / Korumalı Süreç";
                    }

                    procBag.Add(item);
                }
                catch { }
                finally
                {
                    try { p.Dispose(); } catch { }
                }
            });

            var procItems = procBag.ToList();

            // Deduplicate executable paths before Authenticode checks so multi-process apps
            // (Chrome, Edge, Electron, svchost) are verified once instead of hashed N times concurrently.
            var uniquePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in procItems)
            {
                if (!string.IsNullOrEmpty(item.Path) && item.Path != "Sistem / Korumalı Süreç" && File.Exists(item.Path))
                {
                    uniquePaths.Add(item.Path);
                }
            }

            var authMap = new ConcurrentDictionary<string, (bool IsSigned, string Signer, bool HasUntrustedCert)>(StringComparer.OrdinalIgnoreCase);
            int authMaxPar = Math.Max(4, Math.Min(8, Environment.ProcessorCount));
            Parallel.ForEach(uniquePaths, new ParallelOptions { MaxDegreeOfParallelism = authMaxPar }, path =>
            {
                try
                {
                    authMap[path] = CheckAuthenticode(path, true);
                }
                catch { }
            });

            var procByPid = new Dictionary<int, ProcessItem>(procItems.Count);
            foreach (var item in procItems)
            {
                if (!string.IsNullOrEmpty(item.Path) && authMap.TryGetValue(item.Path, out var auth))
                {
                    item.IsSigned = auth.IsSigned;
                    if (auth.HasUntrustedCert && !auth.IsSigned)
                    {
                        item.RiskScore += 45;
                        item.Reasons.Add("Güvenilmeyen / Self-Signed sertifikalı yürütülebilir süreç");
                    }
                }

                string lowerName = item.Name.ToLowerInvariant();
                string lowerPath = item.Path.ToLowerInvariant();

                foreach (var s in db.SuspiciousProcessNamesLower)
                {
                    if (lowerName.Contains(s))
                    {
                        item.RiskScore += 85;
                        item.Status = "INFECTED";
                        item.Reasons.Add($"Bilinen zararlı veya saldırı aracı süreç adı: {item.Name}");
                        break;
                    }
                }

                var (highRiskDrop, unsignedAppData) = ClassifyProcessDropPath(lowerPath);
                if (highRiskDrop)
                {
                    item.RiskScore += item.IsSigned ? 25 : 65;
                    if (item.Status == "CLEAN") item.Status = item.RiskScore >= 70 ? "INFECTED" : "SUSPICIOUS";
                    item.Reasons.Add("Riskli kullanıcı/geçici dizininden (Temp/Public/Downloads/Desktop/ProgramData) çalışan süreç");
                }
                else if (unsignedAppData && !item.IsSigned)
                {
                    item.RiskScore += 55;
                    if (item.Status == "CLEAN") item.Status = item.RiskScore >= 70 ? "INFECTED" : "SUSPICIOUS";
                    item.Reasons.Add("Doğrulanmamış AppData konumundan çalışan imzasız süreç");
                }

                procByPid[item.Pid] = item;
            }

            report.Processes = procItems
                .OrderByDescending(x => x.RiskScore)
                .ThenByDescending(x => x.MemoryMb)
                .Take(70)
                .ToList();
            report.SuspiciousProcesses = procItems.Count(x => x.RiskScore >= 40);

            // Kernel TCP + UDP Table (IPv4 + IPv6) with Real PID & LOLBin Egress Correlation
            try
            {
                var conns = NativeNetHelper.GetTcpConnectionsWithPid();
                var udpEndpoints = NativeNetHelper.GetUdpEndpointsWithPid();
                report.ActiveConnections = conns.Count;
                var allNetItems = new List<NetworkConnectionItem>(conns.Count + 32);

                foreach (var c in conns)
                {
                    pidNameMap.TryGetValue(c.Pid, out var pName);
                    procByPid.TryGetValue(c.Pid, out var procRef);
                    string procPath = (procRef?.Path != null && procRef.Path != "Sistem / Korumalı Süreç") ? procRef.Path : "";
                    bool procSigned = procRef?.IsSigned ?? false;
                    int procRisk = procRef?.RiskScore ?? 0;

                    var netItem = new NetworkConnectionItem
                    {
                        Pid = c.Pid,
                        ProcessName = string.IsNullOrEmpty(pName) ? "System" : pName,
                        LocalAddress = c.LocalAddr,
                        LocalPort = c.LocalPort,
                        RemoteAddress = c.RemoteAddr,
                        RemotePort = c.RemotePort,
                        State = c.State,
                        ExecutablePath = procPath,
                        IsSigned = procSigned,
                        RiskScore = procRisk
                    };

                    bool isRemoteHost = !string.IsNullOrEmpty(netItem.RemoteAddress) &&
                        netItem.RemoteAddress != "0.0.0.0" &&
                        netItem.RemoteAddress != "127.0.0.1" &&
                        netItem.RemoteAddress != "::" &&
                        netItem.RemoteAddress != "::1";
                    if (db.SuspiciousPortSet.Contains(netItem.RemotePort) || db.SuspiciousPortSet.Contains(netItem.LocalPort))
                    {
                        netItem.IsSuspicious = true;
                        netItem.RiskScore = Math.Max(netItem.RiskScore, 90);
                        netItem.Reason = $"Şüpheli RAT / C2 Portu ({(db.SuspiciousPortSet.Contains(netItem.RemotePort) ? netItem.RemotePort : netItem.LocalPort)})";
                    }
                    else if (isRemoteHost && (netItem.State == "ESTABLISHED" || netItem.State == "SYN_SENT") && s_lolbinNetNames.Contains(netItem.ProcessName))
                    {
                        netItem.IsSuspicious = true;
                        netItem.RiskScore = Math.Max(netItem.RiskScore, 92);
                        netItem.Reason = $"LOLBin Dış Ağ Bağlantısı ({netItem.ProcessName} -> {netItem.RemoteAddress}:{netItem.RemotePort})";
                    }
                    else if (isRemoteHost && (netItem.State == "ESTABLISHED" || netItem.State == "SYN_SENT") && procRef != null && !procRef.IsSigned && procRef.RiskScore >= 50)
                    {
                        netItem.IsSuspicious = true;
                        netItem.Reason = $"RAT Davranışı: İmzasız Riskli Dizin Süreci Dış Bağlantısı ({netItem.RemoteAddress}:{netItem.RemotePort})";
                    }

                    allNetItems.Add(netItem);
                }

                foreach (var u in udpEndpoints)
                {
                    if (!db.SuspiciousPortSet.Contains(u.LocalPort)) continue;
                    pidNameMap.TryGetValue(u.Pid, out var pName);
                    procByPid.TryGetValue(u.Pid, out var procRef);
                    allNetItems.Add(new NetworkConnectionItem
                    {
                        Pid = u.Pid,
                        ProcessName = string.IsNullOrEmpty(pName) ? "System" : pName,
                        LocalAddress = u.LocalAddr,
                        LocalPort = u.LocalPort,
                        RemoteAddress = "*",
                        RemotePort = 0,
                        State = "UDP_LISTEN",
                        IsSuspicious = true,
                        Reason = $"Şüpheli RAT / C2 UDP Portu ({u.LocalPort})",
                        ExecutablePath = (procRef?.Path != null && procRef.Path != "Sistem / Korumalı Süreç") ? procRef.Path : "",
                        IsSigned = procRef?.IsSigned ?? false,
                        RiskScore = Math.Max(procRef?.RiskScore ?? 0, 88)
                    });
                }

                report.SuspiciousConnections = allNetItems.Count(x => x.IsSuspicious);
                report.Connections = allNetItems
                    .OrderByDescending(x => x.IsSuspicious ? 1 : 0)
                    .ThenByDescending(x => (x.State == "ESTABLISHED" || x.State == "SYN_SENT") ? 1 : 0)
                    .ThenByDescending(x => x.RiskScore)
                    .Take(200)
                    .ToList();
            }
            catch { }

            return report;
        }

        static object BuildSuspiciousSocketsReport(MalwareDb db)
        {
            var suspicious = new List<NetworkConnectionItem>();
            int totalConns = 0;
            try
            {
                var conns = NativeNetHelper.GetTcpConnectionsWithPid();
                var udpEndpoints = NativeNetHelper.GetUdpEndpointsWithPid();
                totalConns = conns.Count;

                var candidateConns = new List<(int Pid, string LocalAddr, int LocalPort, string RemoteAddr, int RemotePort, string State, bool IsRemote)>();
                var neededPids = new HashSet<int>();

                foreach (var c in conns)
                {
                    bool isRemote = !string.IsNullOrEmpty(c.RemoteAddr) &&
                        c.RemoteAddr != "0.0.0.0" &&
                        c.RemoteAddr != "127.0.0.1" &&
                        c.RemoteAddr != "::" &&
                        c.RemoteAddr != "::1";
                    bool isSuspPort = db.SuspiciousPortSet.Contains(c.RemotePort) || db.SuspiciousPortSet.Contains(c.LocalPort);
                    bool isActiveExternal = isRemote && (c.State == "ESTABLISHED" || c.State == "SYN_SENT");

                    if (isSuspPort || isActiveExternal)
                    {
                        candidateConns.Add((c.Pid, c.LocalAddr, c.LocalPort, c.RemoteAddr, c.RemotePort, c.State, isRemote));
                        if (c.Pid > 4) neededPids.Add(c.Pid);
                    }
                }

                var suspUdps = new List<(int Pid, string LocalAddr, int LocalPort)>();
                foreach (var u in udpEndpoints)
                {
                    if (db.SuspiciousPortSet.Contains(u.LocalPort))
                    {
                        suspUdps.Add(u);
                        if (u.Pid > 4) neededPids.Add(u.Pid);
                    }
                }

                var procMeta = new Dictionary<int, (string Name, string ExePath, bool IsSigned, int RiskScore)>(neededPids.Count);
                foreach (int pid in neededPids)
                {
                    try
                    {
                        using var p = Process.GetProcessById(pid);
                        string name = p.ProcessName;
                        string pPath = "";
                        try { pPath = p.MainModule?.FileName ?? ""; } catch { }

                        bool isSigned = false;
                        int risk = 0;
                        string lowerName = name.ToLowerInvariant();
                        foreach (var s in db.SuspiciousProcessNamesLower)
                        {
                            if (lowerName.Contains(s))
                            {
                                risk += 85;
                                break;
                            }
                        }

                        string lowerPath = pPath.ToLowerInvariant();
                        var (highRiskDrop, unsignedAppData) = ClassifyProcessDropPath(lowerPath);

                        if ((highRiskDrop || unsignedAppData || risk > 0) && !string.IsNullOrEmpty(pPath) && File.Exists(pPath))
                        {
                            var (signed, _, hasUntrusted) = CheckAuthenticode(pPath);
                            isSigned = signed;
                            if (hasUntrusted && !signed) risk += 45;
                        }

                        if (highRiskDrop)
                            risk += isSigned ? 25 : 65;
                        else if (unsignedAppData && !isSigned)
                            risk += 55;

                        procMeta[pid] = (name, pPath, isSigned, risk);
                    }
                    catch { }
                }

                foreach (var c in candidateConns)
                {
                    string procName = "System";
                    string exePath = "";
                    bool isSigned = false;
                    int riskScore = 0;
                    if (procMeta.TryGetValue(c.Pid, out var meta))
                    {
                        procName = string.IsNullOrEmpty(meta.Name) ? "System" : meta.Name;
                        exePath = meta.ExePath;
                        isSigned = meta.IsSigned;
                        riskScore = meta.RiskScore;
                    }

                    bool isSusp = false;
                    string reason = "";
                    if (db.SuspiciousPortSet.Contains(c.RemotePort) || db.SuspiciousPortSet.Contains(c.LocalPort))
                    {
                        isSusp = true;
                        riskScore = Math.Max(riskScore, 90);
                        reason = $"Şüpheli RAT / C2 Portu ({(db.SuspiciousPortSet.Contains(c.RemotePort) ? c.RemotePort : c.LocalPort)})";
                    }
                    else if (c.IsRemote && (c.State == "ESTABLISHED" || c.State == "SYN_SENT") && s_lolbinNetNames.Contains(procName))
                    {
                        isSusp = true;
                        riskScore = Math.Max(riskScore, 92);
                        reason = $"LOLBin Dış Ağ Bağlantısı ({procName} -> {c.RemoteAddr}:{c.RemotePort})";
                    }
                    else if (c.IsRemote && !isSigned && riskScore >= 50)
                    {
                        isSusp = true;
                        reason = $"RAT Davranışı: İmzasız Riskli Dizin Süreci Dış Bağlantısı ({c.RemoteAddr}:{c.RemotePort})";
                    }

                    if (isSusp)
                    {
                        suspicious.Add(new NetworkConnectionItem
                        {
                            Pid = c.Pid,
                            ProcessName = procName,
                            LocalAddress = c.LocalAddr,
                            LocalPort = c.LocalPort,
                            RemoteAddress = c.RemoteAddr,
                            RemotePort = c.RemotePort,
                            State = c.State,
                            IsSuspicious = true,
                            Reason = reason,
                            ExecutablePath = exePath,
                            IsSigned = isSigned,
                            RiskScore = riskScore
                        });
                    }
                }

                foreach (var u in suspUdps)
                {
                    string procName = "System";
                    string exePath = "";
                    bool isSigned = false;
                    int riskScore = 88;
                    if (procMeta.TryGetValue(u.Pid, out var meta))
                    {
                        procName = string.IsNullOrEmpty(meta.Name) ? "System" : meta.Name;
                        exePath = meta.ExePath;
                        isSigned = meta.IsSigned;
                        riskScore = Math.Max(riskScore, meta.RiskScore);
                    }
                    suspicious.Add(new NetworkConnectionItem
                    {
                        Pid = u.Pid,
                        ProcessName = procName,
                        LocalAddress = u.LocalAddr,
                        LocalPort = u.LocalPort,
                        RemoteAddress = "*",
                        RemotePort = 0,
                        State = "UDP_LISTEN",
                        IsSuspicious = true,
                        Reason = $"Şüpheli RAT / C2 UDP Portu ({u.LocalPort})",
                        ExecutablePath = exePath,
                        IsSigned = isSigned,
                        RiskScore = riskScore
                    });
                }
            }
            catch { }

            return new { connections = suspicious, active_connections = totalConns };
        }

        static void RunProcessesAndNetwork(string dbPath)
        {
            var db = LoadDb(dbPath);
            var report = BuildProcessesAndNetworkReport(db);
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine(JsonSerializer.Serialize(report));
        }

        static long GetTotalNetworkBytes()
        {
            long sum = 0;
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus == OperationalStatus.Up && ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    {
                        var st = ni.GetIPv4Statistics();
                        sum += st.BytesReceived + st.BytesSent;
                    }
                }
            }
            catch { }
            return sum;
        }

        static void RunDaemon(string dbPath)
        {
            Console.InputEncoding = Encoding.UTF8;
            Console.OutputEncoding = Encoding.UTF8;
            var db = LoadDb(dbPath);
            Console.WriteLine("{\"kind\":\"ready\"}");
            Console.Out.Flush();
            TrimWorkingSet();

            int cmdCount = 0;
            string? line;
            while ((line = Console.ReadLine()) != null)
            {
                if (line.Length > 2 * 1024 * 1024)
                {
                    Console.WriteLine("{\"id\":\"\",\"ok\":false,\"error\":\"Request too large\"}");
                    Console.Out.Flush();
                    continue;
                }
                line = line.Trim().TrimStart('\uFEFF');
                if (string.IsNullOrWhiteSpace(line)) continue;
                string reqId = "";
                try
                {
                    using var doc = JsonDocument.Parse(line);
                    var root = doc.RootElement;
                    reqId = root.TryGetProperty("id", out var idEl) ? (idEl.GetString() ?? "") : "";
                    string cmd = root.TryGetProperty("cmd", out var cmdEl) ? (cmdEl.GetString() ?? "") : "";

                    if (cmd == "scanfile")
                    {
                        string target = root.TryGetProperty("path", out var pEl) ? (pEl.GetString() ?? "") : "";
                        var res = AnalyzeSingleFile(target, db, false);
                        Console.WriteLine(JsonSerializer.Serialize(new { id = reqId, ok = true, data = res }));
                    }
                    else if (cmd == "procnet")
                    {
                        var report = BuildProcessesAndNetworkReport(db);
                        Console.WriteLine(JsonSerializer.Serialize(new { id = reqId, ok = true, data = report }));
                        TrimWorkingSet();
                    }
                    else if (cmd == "netsockets" || cmd == "netwatch")
                    {
                        var report = BuildSuspiciousSocketsReport(db);
                        Console.WriteLine(JsonSerializer.Serialize(new { id = reqId, ok = true, data = report }));
                    }
                    else if (cmd == "netbytes")
                    {
                        Console.WriteLine(JsonSerializer.Serialize(new { id = reqId, ok = true, totalBytes = GetTotalNetworkBytes() }));
                    }
                    else if (cmd == "sysfolders")
                    {
                        var (dl, dk, st) = ResolveSpecialFolders();
                        var removableDrives = GetRemovableDriveInfos();
                        var osEdition = ResolveOsEditionLabel();
                        Console.WriteLine(JsonSerializer.Serialize(new
                        {
                            id = reqId,
                            ok = true,
                            data = new { downloads = dl, desktop = dk, startup = st, removableDrives, osEdition }
                        }));
                    }
                    else if (cmd == "drives")
                    {
                        Console.WriteLine(JsonSerializer.Serialize(new
                        {
                            id = reqId,
                            ok = true,
                            removableDrives = GetRemovableDriveInfos()
                        }));
                    }
                    else if (cmd == "reload_db")
                    {
                        db = LoadDb(dbPath);
                        Console.WriteLine(JsonSerializer.Serialize(new { id = reqId, ok = true }));
                    }
                    else
                    {
                        Console.WriteLine(JsonSerializer.Serialize(new { id = reqId, ok = false, error = "Unknown cmd: " + cmd }));
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(JsonSerializer.Serialize(new { id = reqId, ok = false, error = ex.Message }));
                }
                Console.Out.Flush();
                if (++cmdCount % 80 == 0)
                {
                    TrimWorkingSet();
                }
            }
        }

        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            if (args.Length == 0)
            {
                Console.WriteLine("{\"error\": \"Usage: AegisScanner <scan|quickscan|scanfile|procnet|daemon> [args]\"}");
                return;
            }

            string mode = args[0].ToLowerInvariant();
            string defaultDb = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "..", "signatures", "malware_db.json");
            if (!File.Exists(defaultDb))
            {
                defaultDb = Path.Combine(Directory.GetCurrentDirectory(), "signatures", "malware_db.json");
            }

            bool streamMode = args.Any(a => a.Equals("--stream", StringComparison.OrdinalIgnoreCase));
            var filteredArgs = new List<string>();
            for (int idx = 0; idx < args.Length; idx++)
            {
                if (args[idx].Equals("--stream", StringComparison.OrdinalIgnoreCase)) continue;
                if (args[idx].StartsWith("--tier=", StringComparison.OrdinalIgnoreCase))
                {
                    ActiveTier = args[idx].Substring(7).ToLowerInvariant();
                    continue;
                }
                if (args[idx].Equals("--tier", StringComparison.OrdinalIgnoreCase) && idx + 1 < args.Length)
                {
                    ActiveTier = args[idx + 1].ToLowerInvariant();
                    idx++;
                    continue;
                }
                filteredArgs.Add(args[idx]);
            }
            var cleanArgs = filteredArgs.ToArray();

            if (mode == "scan")
            {
                string target = cleanArgs.Length > 1 ? cleanArgs[1] : Directory.GetCurrentDirectory();
                string dbPath = cleanArgs.Length > 2 ? cleanArgs[2] : defaultDb;
                RunScan(new List<(string, int, int)> { (target, 15000, 5) }, target, dbPath, streamMode);
            }
            else if (mode == "quickscan")
            {
                string dbPath = cleanArgs.Length > 1 ? cleanArgs[1] : defaultDb;
                string extraZone = cleanArgs.Length > 2 ? cleanArgs[2] : "";
                RunQuickScan(dbPath, extraZone, streamMode);
            }
            else if (mode == "fullscan")
            {
                string dbPath = cleanArgs.Length > 1 ? cleanArgs[1] : defaultDb;
                string extraZone = cleanArgs.Length > 2 ? cleanArgs[2] : "";
                RunFullScan(dbPath, extraZone, streamMode);
            }
            else if (mode == "scanfile")
            {
                string target = cleanArgs.Length > 1 ? cleanArgs[1] : "";
                string dbPath = cleanArgs.Length > 2 ? cleanArgs[2] : defaultDb;
                var db = LoadDb(dbPath);
                var res = AnalyzeSingleFile(target, db, false);
                Console.WriteLine(JsonSerializer.Serialize(res));
            }
            else if (mode == "procnet")
            {
                string dbPath = cleanArgs.Length > 1 ? cleanArgs[1] : defaultDb;
                RunProcessesAndNetwork(dbPath);
            }
            else if (mode == "daemon")
            {
                string dbPath = cleanArgs.Length > 1 ? cleanArgs[1] : defaultDb;
                RunDaemon(dbPath);
            }
        }
    }
}
