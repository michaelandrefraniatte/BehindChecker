using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;
using System.Threading;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows.Forms;
namespace ServerBehindChecker
{
    internal class Program
    {
        [DllImport("winmm.dll", EntryPoint = "timeBeginPeriod")]
        public static extern uint TimeBeginPeriod(uint ms);
        [DllImport("winmm.dll", EntryPoint = "timeEndPeriod")]
        public static extern uint TimeEndPeriod(uint ms);
        [DllImport("ntdll.dll", EntryPoint = "NtSetTimerResolution")]
        public static extern void NtSetTimerResolution(uint DesiredResolution, bool SetResolution, ref uint CurrentResolution);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetConsoleCtrlHandler(ConsoleEventDelegate callback, bool add);
        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        private static extern IntPtr GetConsoleWindow();
        [DllImport("User32.dll", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ShowWindow([In] IntPtr hWnd, [In] Int32 nCmdShow);
        const Int32 SW_MINIMIZE = 6;
        static ConsoleEventDelegate handler;
        private delegate bool ConsoleEventDelegate(int eventType);
        public static ThreadStart threadstart;
        public static Thread thread;
        public static uint CurrentResolution = 0;
        private static bool closed = false;
        private static List<string> RemoteAdrrs = new List<string>();
        private static string hostname = "";
        private static string RemoteAdrr = "0.0.0.0";
        private static IPAddress Addr;
        private static bool checking;
        static void Main(string[] args)
        {
            MinimizeConsoleWindow();
            handler = new ConsoleEventDelegate(ConsoleEventCallback);
            SetConsoleCtrlHandler(handler, true);
            bool runelevated = false;
            bool oneinstanceonly = true;
            try
            {
                TimeBeginPeriod(1);
                NtSetTimerResolution(1, true, ref CurrentResolution);
                SetProcessPriority();
                if (oneinstanceonly)
                {
                    if (AlreadyRunning())
                    {
                        return;
                    }
                }
                if (runelevated)
                {
                    if (!hasAdminRights())
                    {
                        RunElevated();
                        return;
                    }
                }
            }
            catch
            {
                return;
            }
            Task.Run(() => Start());
            Console.ReadLine();
        }
        public static bool hasAdminRights()
        {
            WindowsPrincipal principal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        public static void RunElevated()
        {
            try
            {
                ProcessStartInfo processInfo = new ProcessStartInfo();
                processInfo.Verb = "runas";
                processInfo.FileName = Application.ExecutablePath;
                Process.Start(processInfo);
            }
            catch { }
        }
        private static void SetProcessPriority()
        {
            using (Process p = Process.GetCurrentProcess())
            {
                p.PriorityClass = ProcessPriorityClass.RealTime;
            }
        }
        private static bool AlreadyRunning()
        {
            String thisprocessname = Process.GetCurrentProcess().ProcessName;
            Process[] processes = Process.GetProcessesByName(thisprocessname);
            if (processes.Length > 1)
                return true;
            else
                return false;
        }
        private static void MinimizeConsoleWindow()
        {
            IntPtr hWndConsole = GetConsoleWindow();
            ShowWindow(hWndConsole, SW_MINIMIZE);
        }
        static bool ConsoleEventCallback(int eventType)
        {
            if (eventType == 2)
            {
                threadstart = new ThreadStart(FormClose);
                thread = new Thread(threadstart);
                thread.Start();
            }
            return false;
        }
        private static void FormClose()
        {
            closed = true;
            TimeEndPeriod(1);
        }
        public static void Start()
        {
            while (!closed)
            {
                IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
                TcpConnectionInformation[] connections = properties.GetActiveTcpConnections();
                foreach (TcpConnectionInformation connection in connections)
                {
                    try
                    {
                        Addr = connection.RemoteEndPoint.Address;
                        RemoteAdrr = Addr.ToString();
                        if (RemoteAdrr != "::1" & RemoteAdrr != "127.0.0.1" & RemoteAdrr != "0.0.0.0")
                        {
                            RemoteAdrr += ":" + connection.RemoteEndPoint.Port;
                            checking = false;
                            foreach (string remoteaddrs in RemoteAdrrs)
                            {
                                if (RemoteAdrr == remoteaddrs)
                                {
                                    checking = true;
                                    break;
                                }
                                Thread.Sleep(1);
                            }
                            if (!checking)
                            {
                                RemoteAdrrs.Add(RemoteAdrr);
                                IPHostEntry hostEntry = Dns.GetHostEntry(Addr.ToString());
                                hostname = hostEntry.HostName;
                                Console.WriteLine(hostname + ", " + RemoteAdrr);
                                using (StreamWriter sw = File.AppendText("record.txt"))
                                {
                                    sw.WriteLine(hostname + ", " + RemoteAdrr);
                                    sw.Close();
                                }
                            }
                        }
                    }
                    catch
                    {
                        Console.WriteLine(RemoteAdrr);
                        using (StreamWriter createdfile = File.AppendText("record.txt"))
                        {
                            createdfile.WriteLine(RemoteAdrr);
                            createdfile.Close();
                        }
                    }
                    if (closed)
                    {
                        return;
                    }
                    Thread.Sleep(1);
                }
                Thread.Sleep(1);
            }
        }
    }
}