using System;
using System.IO;
using System.Threading;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Diagnostics;
using System.Windows.Forms;
using NetFwTypeLib;
using System.Collections.Generic;
using System.Linq;

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
        public static Thread thread;
        public static uint CurrentResolution = 0;
        public static int processid = 0;
        private static INetFwRule2 newRule;
        private static INetFwPolicy2 firewallpolicy;
        private static List<string> list = new List<string>(), templist = new List<string>();
        private static string ip;
        static void Main(string[] args)
        {
            TimeBeginPeriod(1);
            NtSetTimerResolution(1, true, ref CurrentResolution);
            SetProcessPriority();
            bool runelevated = true;
            bool oneinstanceonly = false;
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
            Console.WriteLine("\tEnter a IP Range like 192.168.1.0-192.168.1.12");
            string IPRange = Console.ReadLine();
            string[] IPRangeElements = IPRange.Split('-');
            string IPStart = IPRangeElements[0];
            string[] IPStartElements = IPStart.Split('.');
            string IPEnd = IPRangeElements[1];
            int IP0 = Convert.ToInt32(IPStartElements[0]), IP1 = Convert.ToInt32(IPStartElements[1]), IP2 = Convert.ToInt32(IPStartElements[2]), IP3 = Convert.ToInt32(IPStartElements[3]);
            do
            {
                ip = IP0 + "." + IP1 + "." + IP2 + "." + IP3;
                bool foundrouter = SearchRouter(ip);
                if (foundrouter)
                {
                    list.Add(ip);
                    Console.WriteLine("router behind: " + ip);
                }
                if (!foundrouter | ip == IPEnd)
                {
                    if (templist.Count == 1)
                    {
                        addToFirewall(templist[0]);
                        using (StreamWriter streamwriter = File.AppendText(IPStart + "-" + IPEnd + ".txt"))
                        {
                            streamwriter.WriteLine(templist[0]);
                            streamwriter.Close();
                        }
                    }
                    if (templist.Count > 1)
                    {
                        addToFirewall(templist[0] + "-" + templist[templist.Count - 1]);
                        using (StreamWriter streamwriter = File.AppendText(IPStart + "-" + IPEnd + ".txt"))
                        {
                            streamwriter.WriteLine(templist[0] + "-" + templist[templist.Count - 1]);
                            streamwriter.Close();
                        }
                    }
                    templist = list;
                    list.Clear();
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
            while (ip != IPEnd);
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
        private static void addToFirewall(string IP)
        {
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
    }
}