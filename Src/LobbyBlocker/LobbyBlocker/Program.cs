using System;
using System.Threading;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Security.Principal;
using System.Diagnostics;
using System.Collections.Generic;
using System.Windows.Forms;
using System.Net.NetworkInformation;
using NetFwTypeLib;
namespace BehindBlocker
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
        public static int processid = 0;
        private static bool closed = false;
        private static List<string> RemoteAdrrs = new List<string>();
        private static List<string> scaledips = new List<string>();
        private static string RemoteAdrr = "0.0.0.0", remoteip, remoteport;
        private static IPAddress Addr;
        private static bool checking, checkingscaledip;
        private static INetFwRule2 newRule;
        private static INetFwPolicy2 firewallpolicy;
        static void Main(string[] args)
        {
            MinimizeConsoleWindow();
            handler = new ConsoleEventDelegate(ConsoleEventCallback);
            SetConsoleCtrlHandler(handler, true);
            bool runelevated = true;
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
            Console.ReadKey();
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
                        remoteip = RemoteAdrr;
                        remoteport = connection.RemoteEndPoint.Port.ToString();
                        if (RemoteAdrr != "::1" & RemoteAdrr != "127.0.0.1" & RemoteAdrr != "0.0.0.0")
                        {
                            RemoteAdrr = remoteip + ":" + remoteport;
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
                                if (IsServer(remoteip) & !Dns.GetHostEntry(Addr.ToString()).HostName.EndsWith(".r.cloudfront.net"))
                                {
                                    Console.WriteLine(RemoteAdrr + ", Blocked");
                                    addToFirewall(remoteip);
                                }
                                else
                                {
                                    Console.WriteLine(RemoteAdrr);
                                }
                            }
                        }
                    }
                    catch
                    {
                        RemoteAdrrs.Add(RemoteAdrr);
                        if (IsServer(remoteip))
                        {
                            Console.WriteLine(RemoteAdrr + ", Blocked");
                            addToFirewall(remoteip);
                        }
                        else
                        {
                            Console.WriteLine(RemoteAdrr);
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
        private static bool IsServer(string IP)
        {
            try
            {
                IPHostEntry hostEntry = Dns.GetHostEntry(IPAddress.Parse(IP));
                IPAddress ipAddress = hostEntry.AddressList[0];
                IPEndPoint ip = new IPEndPoint(ipAddress, 3074);
                Socket server = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { Blocking = false, UseOnlyOverlappedIO = true, DontFragment = false, EnableBroadcast = true };
                server.BeginConnect(ip, null, null).AsyncWaitHandle.WaitOne(1, true);
                server.Shutdown(SocketShutdown.Both);
                server.Close();
                return true;
            }
            catch
            {
                return false;
            }
        }
        private static string getScaleIP(string IP)
        {
            string[] ipelements = IP.Split('.');
            IP = ipelements[0] + "." + ipelements[1] + ".0.0-" + ipelements[0] + "." + ipelements[1] + ".255.255";
            return IP;
        }
        private static void addToFirewall(string IP)
        {
            IP = getScaleIP(IP);
            checkingscaledip = false;
            foreach (string scaledip in scaledips)
            {
                if (IP == scaledip)
                {
                    checkingscaledip = true;
                    break;
                }
                Thread.Sleep(1);
            }
            if (!checkingscaledip)
            {
                scaledips.Add(IP);
                newRule = (INetFwRule2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                newRule.Name = IP;
                newRule.Protocol = (int)NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_ANY;
                newRule.RemoteAddresses = IP;
                newRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT;
                newRule.Enabled = true;
                newRule.InterfaceTypes = "All";
                newRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                newRule.EdgeTraversal = false;
                firewallpolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                firewallpolicy.Rules.Add(newRule);
            }
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
        }
    }
}