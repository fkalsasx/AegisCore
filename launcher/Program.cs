using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace AegisCoreLauncher;

internal static class Program
{
    private const string AppTitle = "AegisCore Endpoint Security";
    private const string MutexName = @"Local\AegisCore_EndpointSecurity_v6";
    private const string DashboardUrl = "http://127.0.0.1:4880";
    private const int DashboardPort = 4880;

    private const uint WM_APP_TRAY = 0x8001;
    private const uint WM_DESTROY = 0x0002;
    private const uint WM_CLOSE = 0x0010;
    private const uint WM_QUERYENDSESSION = 0x0011;
    private const uint WM_ENDSESSION = 0x0016;
    private const uint WM_COMMAND = 0x0111;
    private const uint WM_LBUTTONDBLCLK = 0x0203;
    private const uint WM_RBUTTONUP = 0x0205;
    private const uint WM_CONTEXTMENU = 0x007B;

    private const uint NIM_ADD = 0x00000000;
    private const uint NIM_DELETE = 0x00000002;
    private const uint NIF_MESSAGE = 0x00000001;
    private const uint NIF_ICON = 0x00000002;
    private const uint NIF_TIP = 0x00000004;

    private const uint MF_STRING = 0x00000000;
    private const uint MF_SEPARATOR = 0x00000800;
    private const uint TPM_RIGHTBUTTON = 0x0002;
    private const uint TPM_BOTTOMALIGN = 0x0020;

    private const uint IDM_OPEN_APP = 1001;
    private const uint IDM_OPEN_BROWSER = 1002;
    private const uint IDM_EXIT = 1003;

    private const uint MB_OK = 0x00000000;
    private const uint MB_ICONERROR = 0x00000010;

    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const int JobObjectExtendedLimitInformation = 9;

    private static Process? s_nodeProc;
    private static IntPtr s_jobHandle = IntPtr.Zero;
    private static IntPtr s_hwnd = IntPtr.Zero;
    private static IntPtr s_trayIcon = IntPtr.Zero;
    private static bool s_trayAdded;
    private static WndProcDelegate? s_wndProcRef;
    private static volatile bool s_shuttingDown;

    private delegate IntPtr WndProcDelegate(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [STAThread]
    private static int Main(string[] args)
    {
        bool noBrowser = args.Any(a => a.Equals("--no-browser", StringComparison.OrdinalIgnoreCase)
            || a.Equals("--startup", StringComparison.OrdinalIgnoreCase)
            || a.Equals("--minimized", StringComparison.OrdinalIgnoreCase));
        bool checkOnly = args.Any(a => a.Equals("--check", StringComparison.OrdinalIgnoreCase));

        string appDir = AppContext.BaseDirectory.TrimEnd('\\');
        string serverPath = Path.Combine(appDir, "server.js");
        if (!File.Exists(serverPath))
        {
            string parentServer = Path.GetFullPath(Path.Combine(appDir, "..", "server.js"));
            if (File.Exists(parentServer))
            {
                appDir = Path.GetDirectoryName(parentServer)!;
                serverPath = parentServer;
            }
        }

        string? nodeExe = ResolveNodeBinary(appDir);
        if (checkOnly)
        {
            bool ok = File.Exists(serverPath) && !string.IsNullOrEmpty(nodeExe);
            return ok ? 0 : 1;
        }

        using var mutex = new Mutex(true, MutexName, out bool createdNew);
        if (!createdNew)
        {
            if (!noBrowser)
                OpenDashboardWindow(preferAppMode: true);
            return 0;
        }

        if (!File.Exists(serverPath))
        {
            ShowError($"AegisCore ana servisi (server.js) bulunamadı:\n{serverPath}");
            return 1;
        }

        if (string.IsNullOrEmpty(nodeExe))
        {
            ShowError("Node.js çalışma zamanı bulunamadı.\nLütfen AegisCore tam paketini kullanın veya Node.js 18+ kurun.");
            return 1;
        }

        if (!StartBackendServer(appDir, nodeExe, out string startupError))
        {
            ShowError($"AegisCore çekirdek servisi başlatılamadı:\n{startupError}");
            ShutdownBackend();
            return 1;
        }

        if (!noBrowser)
        {
            OpenDashboardWindow(preferAppMode: true);
        }

        RunTrayMessageLoop();
        ShutdownBackend();
        return 0;
    }

    private static string? ResolveNodeBinary(string appDir)
    {
        string bundled = Path.Combine(appDir, "runtime", "node", "node.exe");
        if (File.Exists(bundled)) return bundled;

        string? pathEnv = Environment.GetEnvironmentVariable("PATH");
        if (!string.IsNullOrEmpty(pathEnv))
        {
            foreach (string dir in pathEnv.Split(';', StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    string candidate = Path.Combine(dir.Trim(), "node.exe");
                    if (File.Exists(candidate)) return candidate;
                }
                catch { }
            }
        }

        string pfNode = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "nodejs", "node.exe");
        return File.Exists(pfNode) ? pfNode : null;
    }

    private static bool StartBackendServer(string appDir, string nodeExe, out string errorMsg)
    {
        errorMsg = "";
        var stderrBuf = new StringBuilder();
        try
        {
            s_jobHandle = CreateKillOnCloseJob();

            var psi = new ProcessStartInfo
            {
                FileName = nodeExe,
                Arguments = "--max-old-space-size=192 --expose-gc server.js",
                WorkingDirectory = appDir,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            psi.Environment["AEGIS_LAUNCHER_PID"] = Environment.ProcessId.ToString();

            s_nodeProc = new Process { StartInfo = psi, EnableRaisingEvents = true };
            s_nodeProc.OutputDataReceived += (_, _) => { };
            s_nodeProc.ErrorDataReceived += (_, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data) && stderrBuf.Length < 1200)
                {
                    lock (stderrBuf) stderrBuf.AppendLine(e.Data);
                }
            };
            s_nodeProc.Exited += (_, _) =>
            {
                if (!s_shuttingDown && s_hwnd != IntPtr.Zero)
                {
                    PostMessageW(s_hwnd, WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
                }
            };

            if (!s_nodeProc.Start())
            {
                errorMsg = "node.exe süreci oluşturulamadı.";
                return false;
            }

            if (s_jobHandle != IntPtr.Zero)
            {
                AssignProcessToJobObject(s_jobHandle, s_nodeProc.Handle);
            }

            s_nodeProc.BeginOutputReadLine();
            s_nodeProc.BeginErrorReadLine();

            // Wait until TCP 127.0.0.1:4880 accepts connections (max 15s)
            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < 15000)
            {
                if (s_nodeProc.HasExited)
                {
                    Thread.Sleep(150);
                    lock (stderrBuf)
                    {
                        errorMsg = stderrBuf.Length > 0
                            ? stderrBuf.ToString().Trim()
                            : $"Sunucu erken kapandı (çıkış kodu: {s_nodeProc.ExitCode}).";
                    }
                    return false;
                }

                if (IsPortOpen("127.0.0.1", DashboardPort, 200))
                {
                    return true;
                }
                Thread.Sleep(150);
            }

            return true;
        }
        catch (Exception ex)
        {
            errorMsg = ex.Message;
            return false;
        }
    }

    private static bool IsPortOpen(string host, int port, int timeoutMs)
    {
        try
        {
            using var client = new TcpClient();
            var task = client.ConnectAsync(host, port);
            return task.Wait(timeoutMs) && client.Connected;
        }
        catch
        {
            return false;
        }
    }

    private static void OpenDashboardWindow(bool preferAppMode)
    {
        try
        {
            if (preferAppMode)
            {
                string[] browserCandidates =
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), @"Microsoft\Edge\Application\msedge.exe"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Microsoft\Edge\Application\msedge.exe"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Google\Chrome\Application\chrome.exe"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), @"Google\Chrome\Application\chrome.exe"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Google\Chrome\Application\chrome.exe")
                };

                foreach (string browser in browserCandidates)
                {
                    if (File.Exists(browser))
                    {
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = browser,
                            Arguments = $"--app={DashboardUrl} --window-size=1280,860",
                            UseShellExecute = false
                        });
                        return;
                    }
                }
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = DashboardUrl,
                UseShellExecute = true
            });
        }
        catch { }
    }

    private static void RunTrayMessageLoop()
    {
        IntPtr hInstance = GetModuleHandleW(null);
        string className = "AegisCoreTrayHiddenWnd";
        s_wndProcRef = WndProc;

        var wc = new WNDCLASSEXW
        {
            cbSize = (uint)Marshal.SizeOf<WNDCLASSEXW>(),
            lpfnWndProc = Marshal.GetFunctionPointerForDelegate(s_wndProcRef),
            hInstance = hInstance,
            lpszClassName = className
        };

        RegisterClassExW(ref wc);

        s_hwnd = CreateWindowExW(
            0, className, AppTitle, 0,
            0, 0, 0, 0,
            IntPtr.Zero, IntPtr.Zero, hInstance, IntPtr.Zero);

        if (s_hwnd == IntPtr.Zero)
        {
            s_nodeProc?.WaitForExit();
            return;
        }

        s_trayIcon = LoadAppIcon(hInstance);
        var nid = new NOTIFYICONDATAW
        {
            cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
            hWnd = s_hwnd,
            uID = 1,
            uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP,
            uCallbackMessage = WM_APP_TRAY,
            hIcon = s_trayIcon,
            szTip = "AegisCore Endpoint Security v6.0"
        };

        s_trayAdded = Shell_NotifyIconW(NIM_ADD, ref nid);

        // Trim launcher working set right after init
        try { SetProcessWorkingSetSize(GetCurrentProcess(), (IntPtr)(-1), (IntPtr)(-1)); } catch { }

        while (GetMessageW(out MSG msg, IntPtr.Zero, 0, 0) > 0)
        {
            TranslateMessage(ref msg);
            DispatchMessageW(ref msg);
        }

        RemoveTrayIcon();
    }

    private static IntPtr LoadAppIcon(IntPtr hInstance)
    {
        IntPtr icon = LoadImageW(hInstance, (IntPtr)32512, 1, 16, 16, 0);
        if (icon != IntPtr.Zero) return icon;

        string? selfExe = Environment.ProcessPath;
        if (!string.IsNullOrEmpty(selfExe) && File.Exists(selfExe))
        {
            IntPtr[] small = new IntPtr[1];
            if (ExtractIconExW(selfExe, 0, null, small, 1) > 0 && small[0] != IntPtr.Zero)
                return small[0];
        }

        return LoadIconW(IntPtr.Zero, (IntPtr)32518); // IDI_SHIELD fallback
    }

    private static void RemoveTrayIcon()
    {
        if (s_trayAdded && s_hwnd != IntPtr.Zero)
        {
            var nid = new NOTIFYICONDATAW
            {
                cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
                hWnd = s_hwnd,
                uID = 1
            };
            Shell_NotifyIconW(NIM_DELETE, ref nid);
            s_trayAdded = false;
        }
        if (s_trayIcon != IntPtr.Zero)
        {
            DestroyIcon(s_trayIcon);
            s_trayIcon = IntPtr.Zero;
        }
    }

    private static IntPtr WndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam)
    {
        switch (msg)
        {
            case WM_APP_TRAY:
                uint trayEvent = (uint)(lParam.ToInt64() & 0xFFFF);
                if (trayEvent == WM_LBUTTONDBLCLK)
                {
                    OpenDashboardWindow(preferAppMode: true);
                }
                else if (trayEvent == WM_RBUTTONUP || trayEvent == WM_CONTEXTMENU)
                {
                    ShowTrayContextMenu(hWnd);
                }
                return IntPtr.Zero;

            case WM_COMMAND:
                uint cmd = (uint)(wParam.ToInt64() & 0xFFFF);
                if (cmd == IDM_OPEN_APP)
                {
                    OpenDashboardWindow(preferAppMode: true);
                }
                else if (cmd == IDM_OPEN_BROWSER)
                {
                    OpenDashboardWindow(preferAppMode: false);
                }
                else if (cmd == IDM_EXIT)
                {
                    s_shuttingDown = true;
                    RemoveTrayIcon();
                    DestroyWindow(hWnd);
                }
                return IntPtr.Zero;

            case WM_QUERYENDSESSION:
                return (IntPtr)1;

            case WM_ENDSESSION:
                if (wParam != IntPtr.Zero)
                {
                    s_shuttingDown = true;
                    RemoveTrayIcon();
                    ShutdownBackend();
                }
                return IntPtr.Zero;

            case WM_CLOSE:
                RemoveTrayIcon();
                DestroyWindow(hWnd);
                return IntPtr.Zero;

            case WM_DESTROY:
                RemoveTrayIcon();
                PostQuitMessage(0);
                return IntPtr.Zero;
        }

        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }

    private static void ShowTrayContextMenu(IntPtr hWnd)
    {
        IntPtr menu = CreatePopupMenu();
        if (menu == IntPtr.Zero) return;
        try
        {
            AppendMenuW(menu, MF_STRING, IDM_OPEN_APP, "AegisCore Panelini Aç");
            AppendMenuW(menu, MF_STRING, IDM_OPEN_BROWSER, "Tarayıcıda Aç (localhost:4880)");
            AppendMenuW(menu, MF_SEPARATOR, 0, null);
            AppendMenuW(menu, MF_STRING, IDM_EXIT, "Çıkış (Korumayı Durdur)");
            SetMenuDefaultItem(menu, IDM_OPEN_APP, 0);

            GetCursorPos(out POINT pt);
            SetForegroundWindow(hWnd);
            TrackPopupMenuEx(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.X, pt.Y, hWnd, IntPtr.Zero);
            PostMessageW(hWnd, 0, IntPtr.Zero, IntPtr.Zero);
        }
        finally
        {
            DestroyMenu(menu);
        }
    }

    private static void ShutdownBackend()
    {
        s_shuttingDown = true;
        try
        {
            if (s_nodeProc != null && !s_nodeProc.HasExited)
            {
                s_nodeProc.Kill(entireProcessTree: true);
                s_nodeProc.WaitForExit(3000);
            }
        }
        catch { }
        finally
        {
            try { s_nodeProc?.Dispose(); } catch { }
            s_nodeProc = null;
        }

        if (s_jobHandle != IntPtr.Zero)
        {
            CloseHandle(s_jobHandle);
            s_jobHandle = IntPtr.Zero;
        }
    }

    private static IntPtr CreateKillOnCloseJob()
    {
        IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
        if (job == IntPtr.Zero) return IntPtr.Zero;

        var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        int size = Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(info, ptr, false);
            if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, ptr, (uint)size))
            {
                CloseHandle(job);
                return IntPtr.Zero;
            }
            return job;
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    private static void ShowError(string message)
    {
        MessageBoxW(IntPtr.Zero, message, AppTitle, MB_OK | MB_ICONERROR);
    }

    #region Win32 P/Invoke

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WNDCLASSEXW
    {
        public uint cbSize;
        public uint style;
        public IntPtr lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        public string? lpszMenuName;
        public string lpszClassName;
        public IntPtr hIconSm;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NOTIFYICONDATAW
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szTip;
        public uint dwState;
        public uint dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szInfo;
        public uint uTimeoutOrVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string szInfoTitle;
        public uint dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT { public int X; public int Y; }

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG
    {
        public IntPtr hwnd;
        public uint message;
        public IntPtr wParam;
        public IntPtr lParam;
        public uint time;
        public POINT pt;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandleW(string? lpModuleName);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern bool SetProcessWorkingSetSize(IntPtr hProcess, IntPtr minSize, IntPtr maxSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string? lpName);

    [DllImport("kernel32.dll")]
    private static extern bool SetInformationJobObject(IntPtr hJob, int infoClass, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);

    [DllImport("kernel32.dll")]
    private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern ushort RegisterClassExW(ref WNDCLASSEXW lpwcx);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateWindowExW(
        uint dwExStyle, string lpClassName, string lpWindowName, uint dwStyle,
        int x, int y, int nWidth, int nHeight,
        IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);

    [DllImport("user32.dll")]
    private static extern IntPtr DefWindowProcW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern int GetMessageW(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

    [DllImport("user32.dll")]
    private static extern bool TranslateMessage(ref MSG lpMsg);

    [DllImport("user32.dll")]
    private static extern IntPtr DispatchMessageW(ref MSG lpMsg);

    [DllImport("user32.dll")]
    private static extern bool PostMessageW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern void PostQuitMessage(int nExitCode);

    [DllImport("user32.dll")]
    private static extern bool DestroyWindow(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);

    [DllImport("user32.dll")]
    private static extern IntPtr CreatePopupMenu();

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern bool AppendMenuW(IntPtr hMenu, uint uFlags, uint uIDNewItem, string? lpNewItem);

    [DllImport("user32.dll")]
    private static extern bool SetMenuDefaultItem(IntPtr hMenu, uint uItem, uint fByPos);

    [DllImport("user32.dll")]
    private static extern bool DestroyMenu(IntPtr hMenu);

    [DllImport("user32.dll")]
    private static extern bool GetCursorPos(out POINT lpPoint);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool TrackPopupMenuEx(IntPtr hMenu, uint uFlags, int x, int y, IntPtr hWnd, IntPtr lptpm);

    [DllImport("user32.dll")]
    private static extern IntPtr LoadIconW(IntPtr hInstance, IntPtr lpIconName);

    [DllImport("user32.dll")]
    private static extern IntPtr LoadImageW(IntPtr hInst, IntPtr lpszName, uint uType, int cxDesired, int cyDesired, uint fuLoad);

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr hIcon);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern bool Shell_NotifyIconW(uint dwMessage, ref NOTIFYICONDATAW lpData);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern uint ExtractIconExW(string lpszFile, int nIconIndex, IntPtr[]? phiconLarge, IntPtr[]? phiconSmall, uint nIcons);

    #endregion
}
