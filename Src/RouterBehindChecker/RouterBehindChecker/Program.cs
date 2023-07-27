using System;
using System.IO;
using System.Threading;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Diagnostics;
using System.Collections.Generic;
using System.Windows.Forms;
namespace RouterBehindChecker
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
            Console.WriteLine("\tIP Start ?");
            string IPStart = Console.ReadLine();
            string[] IPStartElements = IPStart.Split('.');
            Console.WriteLine("\tIP End ?");
            string IPEnd = Console.ReadLine();
            string[] IPEndElements = IPEnd.Split('.');
            int IP0 = Convert.ToInt32(IPStartElements[0]), IP1 = Convert.ToInt32(IPStartElements[1]), IP2 = Convert.ToInt32(IPStartElements[2]), IP3 = Convert.ToInt32(IPStartElements[3]);
            do
            {
                string ip = IP0 + "." + IP1 + "." + IP2 + "." + IP3;
                if (SearchRouter(ip))
                {
                    Console.WriteLine("router behind: " + ip);
                    using (StreamWriter streamwriter = File.AppendText(IPStart + "-" + IPEnd + ".txt"))
                    {
                        streamwriter.WriteLine(ip);
                        streamwriter.Close();
                    }
                }
                else
                {
                    Console.WriteLine(ip);
                }
                IP3++;
                if (IP3 > 255)
                {
                    IP3 = 0;
                    IP2++;
                }
                if (IP2 > 255)
                {
                    IP2 = 0;
                    IP1++;
                }
                if (IP1 > 255)
                {
                    IP1 = 0;
                    IP0++;
                }
                Thread.Sleep(1);
            }
            while (!(IP0 == Convert.ToInt32(IPEndElements[0]) & IP1 == Convert.ToInt32(IPEndElements[1]) & IP2 == Convert.ToInt32(IPEndElements[2]) & IP3 == Convert.ToInt32(IPEndElements[3])));
            Console.ReadKey();
        }
        private static bool SearchRouter(string IP)
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
            TimeEndPeriod(1);
        }
    }
}