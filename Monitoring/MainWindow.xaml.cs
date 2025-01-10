using Microsoft.UI.Xaml;
using System;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;
using Windows.UI.Notifications;
using Windows.Data.Xml.Dom;


namespace Monitoring
{
    public sealed partial class MainWindow : Window
    {

        //############################## THREAT DETECTION VARIABLES ###################################

        string dos_time = "none";
        int dos_counter = 0;
        private DispatcherTimer dos_timer;
        long dos_position = 0;

        long mitm_time_milliseconds = 0;
        long mitm_time = 0;
        int[,] mitm_where = new int[100, 100];
        string[,,,] mitm_rtts = new string[100, 100, 10, 4];
        private DispatcherTimer mitm_timer;
        long mitm_position = 0;

        string[,] icmp_time = new string[100, 3];
        private DispatcherTimer icmp_timer;
        long icmp_position = 0;

        //############################## GENERAL ###################################

        public MainWindow()
        {
            this.InitializeComponent();
            Title = "Network Monitoring";
            setup_timers();
        }

        private void show_notification_dos()
        {
            var toast_xml_text = @"
            <toast>
                <visual>
                    <binding template='ToastGeneric'>
                        <text>Alert</text>
                        <text>Possible DoS attack detected.</text>
                    </binding>
                </visual>
            </toast>";

            var toast_xml = new XmlDocument();
            toast_xml.LoadXml(toast_xml_text);
            var toast = new ToastNotification(toast_xml);
            ToastNotificationManager.CreateToastNotifier().Show(toast);
        }

        private void show_notification_mitm()
        {
            var toast_xml_text = @"
            <toast>
                <visual>
                    <binding template='ToastGeneric'>
                        <text>Alert</text>
                        <text>Possible MITM attack detected.</text>
                    </binding>
                </visual>
            </toast>";

            var toast_xml = new XmlDocument();
            toast_xml.LoadXml(toast_xml_text);
            var toast = new ToastNotification(toast_xml);
            ToastNotificationManager.CreateToastNotifier().Show(toast);
        }

        private void show_notification_icmp()
        {
            var toast_xml_text = @"
            <toast>
                <visual>
                    <binding template='ToastGeneric'>
                        <text>Alert</text>
                        <text>Possible ICMP ping sweep detected.</text>
                    </binding>
                </visual>
            </toast>";

            var toast_xml = new XmlDocument();
            toast_xml.LoadXml(toast_xml_text);
            var toast = new ToastNotification(toast_xml);
            ToastNotificationManager.CreateToastNotifier().Show(toast);
        }

        private void setup_timers()
        {
            dos_timer = new DispatcherTimer();
            dos_timer.Interval = TimeSpan.FromSeconds(5);
            dos_timer.Tick += dos_timer_tick;

            mitm_timer = new DispatcherTimer();
            mitm_timer.Interval = TimeSpan.FromSeconds(5);
            mitm_timer.Tick += mitm_timer_tick;

            icmp_timer = new DispatcherTimer();
            icmp_timer.Interval = TimeSpan.FromSeconds(5);
            icmp_timer.Tick += icmp_timer_tick;
        }

        public void exe_admin(string file, string arg1 = "default")
        {
            Process process = new Process();

            if (!arg1.Equals("default"))
            {
                process.StartInfo.Arguments = arg1;
            }
            process.StartInfo.UseShellExecute = true;
            process.StartInfo.FileName = file;
            process.StartInfo.Verb = "runas";
            try
            {
                process.Start();
            }
            catch (System.ComponentModel.Win32Exception)
            {
                comp_textblock.Text = "Administrator privileges are required." + "\r\n" + "\r\n" + comp_textblock.Text;
            }
        }

        //############################## THREAT DETECTION FUNCTIONS ###################################

        private void dos_timer_tick(object sender, object e)
        {
            detect_dos("../Captures/capture.txt");
        }

        private void mitm_timer_tick(object sender, object e)
        {
            detect_mitm("../Captures/capture.txt");
        }

        private void icmp_timer_tick(object sender, object e)
        {
            detect_icmp("../Captures/capture.txt");
        }

        public void detect_dos(string file, int threshold = 10)
        {
            string text = "";
            using (System.IO.FileStream filestream = new System.IO.FileStream(file, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite))
            {
                filestream.Seek(dos_position, SeekOrigin.Begin);
                using (System.IO.StreamReader streamreader = new System.IO.StreamReader(filestream))
                {
                    text = streamreader.ReadToEnd();
                    dos_position = filestream.Position;
                }
            }

            string[] packets = text.Split("\t");
            string result = "";


            for (int i = 0; i < packets.Length; i++)
            {
                Match timestamp = Regex.Match(packets[i], "\\d{2}:\\d{2}:\\d{2}\\.\\d{9}");
                if (timestamp.Success)
                {
                    if (timestamp.Value.Contains(dos_time))
                    {
                        dos_counter++;
                        if (dos_counter >= threshold)
                        {
                            result = result + "Possible DOS attack detected at " + dos_time + "\r\n";
                            comp_textblock.Text = result + "\r\n" + comp_textblock.Text;
                            show_notification_dos();
                            break;
                        }
                    }
                    else
                    {
                        dos_time = timestamp.Value[..8];
                        dos_counter = 1;
                    }
                }
            }
        }

        public void detect_mitm(string file)
        {
            string text = "";
            using (System.IO.FileStream filestream = new System.IO.FileStream(file, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite))
            {
                filestream.Seek(mitm_position, SeekOrigin.Begin);
                using (System.IO.StreamReader streamreader = new System.IO.StreamReader(filestream))
                {
                    text = streamreader.ReadToEnd();
                    mitm_position = filestream.Position;
                }
            }

            string[] packets = text.Split("\t");
            string all_times = "";
            decimal countt = 0;
            decimal mean = 0;
            string last_time = "";
            string suspect = "";

            for (int i = 0; i < packets.Length; i++)
            {
                if (packets[i].Contains("Flags [S]"))
                {
                    Match timestamp = Regex.Match(packets[i], "(\\d{2}):(\\d{2}):(\\d{2})\\.(\\d{9})");
                    Match addresses = Regex.Match(packets[i], "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d+) > (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d+)");
                    Match sequence = Regex.Match(packets[i], "seq (\\d+)");
                    if (timestamp.Success && addresses.Success && sequence.Success)
                    {
                        mitm_time_milliseconds = long.Parse(timestamp.Groups[4].Value);
                        mitm_time = long.Parse(timestamp.Groups[1].Value) * 60 * 60 + long.Parse(timestamp.Groups[2].Value) * 60 + long.Parse(timestamp.Groups[3].Value);

                        for (int b = 0; b < 100; b++)
                        {
                            if (mitm_rtts[0, b, 0, 0] == null)
                            {
                                mitm_rtts[0, b, 0, 0] = addresses.Groups[1].Value;
                            }
                            if (mitm_rtts[0, b, 0, 0].Equals(addresses.Groups[1].Value))
                            {
                                for (int c = 0; c < 100; c++)
                                {
                                    if (mitm_rtts[c, 0, 0, 0] == null)
                                    {
                                        mitm_rtts[c, 0, 0, 0] = addresses.Groups[2].Value;
                                    }
                                    if (mitm_rtts[c, 0, 0, 0].Equals(addresses.Groups[2].Value))
                                    {
                                        mitm_rtts[c, b, 0, 3] = sequence.Groups[1].Value;
                                        mitm_rtts[c, b, 0, 1] = mitm_time.ToString();
                                        mitm_rtts[c, b, 0, 2] = mitm_time_milliseconds.ToString();
                                        break;
                                    }
                                }
                                break;
                            }
                        }

                    }
                }
                else if (packets[i].Contains("Flags [S.]"))
                {
                    Match addresses = Regex.Match(packets[i], "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d+) > (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d+)");
                    Match ack = Regex.Match(packets[i], "ack (\\d+)");
                    Match timestamp = Regex.Match(packets[i], "(\\d{2}):(\\d{2}):(\\d{2})\\.(\\d{9})");
                    if (addresses.Success && ack.Success && timestamp.Success)
                    {
                        for (int b = 0; b < 100; b++)
                        {
                            if (mitm_rtts[0, b, 0, 0].Equals(addresses.Groups[2].Value))
                            {
                                for (int c = 0; c < 100; c++)
                                {
                                    if (mitm_rtts[c, 0, 0, 0].Equals(addresses.Groups[1].Value))
                                    {
                                        if (mitm_rtts[c, b, 0, 3].Equals((long.Parse(ack.Groups[1].Value) - 1).ToString()))
                                        {
                                            mean = 0;
                                            countt = 0;
                                            all_times = "";
                                            for (int d = 1; d < 10; d++)
                                            {
                                                if (mitm_rtts[c, b, d, 0] != null)
                                                {
                                                    mean = mean + decimal.Parse(mitm_rtts[c, b, d, 0]);
                                                    all_times = all_times + " " + double.Parse(mitm_rtts[c, b, d, 0]);
                                                    countt++;
                                                    if (d == 9)
                                                    {
                                                        mitm_rtts[c, b, mitm_where[c,b], 0] = (decimal.Parse((long.Parse(timestamp.Groups[1].Value) * 60 * 60 + long.Parse(timestamp.Groups[2].Value) * 60 + long.Parse(timestamp.Groups[3].Value)).ToString() + "." + timestamp.Groups[4].Value) - decimal.Parse(mitm_rtts[c, b, 0, 1] + "." + mitm_rtts[c, b, 0, 2])).ToString();
                                                        last_time = mitm_rtts[c, b, mitm_where[c, b], 0];
                                                        if (mitm_where[c, b] < 9)
                                                        {
                                                            mitm_where[c, b]++;
                                                        }
                                                        else
                                                        {
                                                            mitm_where[c, b] = 1;
                                                        }
                                                        break;
                                                    }
                                                }
                                                else
                                                {
                                                    mitm_rtts[c, b, d, 0] = (decimal.Parse((long.Parse(timestamp.Groups[1].Value) * 60 * 60 + long.Parse(timestamp.Groups[2].Value) * 60 + long.Parse(timestamp.Groups[3].Value)).ToString() + "." + timestamp.Groups[4].Value) - decimal.Parse(mitm_rtts[c, b, 0, 1] + "." + mitm_rtts[c, b, 0, 2])).ToString();
                                                    last_time = mitm_rtts[c, b, d, 0];
                                                    break;
                                                }
                                            }
                                            if (mean != 0)
                                            {
                                                mean = mean / countt;
                                                if (decimal.Parse(last_time) > 2 * mean)
                                                {
                                                    suspect = suspect + "Suspicious response time between " + addresses.Groups[1].Value + " and " + addresses.Groups[2].Value + " at " + timestamp.Value + ". " + " (" + last_time + " seconds instead of " + mean + " seconds usually). " + "\r\n";
                                                    comp_textblock.Text = suspect + "\r\n" + comp_textblock.Text;
                                                    show_notification_mitm();
                                                }
                                            }
                                            break;
                                        }


                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }

        public void detect_icmp(string file, int threshold = 10)
        {
            string text = "";
            using (System.IO.FileStream filestream = new System.IO.FileStream(file, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite))
            {
                filestream.Seek(icmp_position, SeekOrigin.Begin);
                using (System.IO.StreamReader streamreader = new System.IO.StreamReader(filestream))
                {
                    text = streamreader.ReadToEnd();
                    icmp_position = filestream.Position;
                }
            }

            string[] packets = text.Split("\t");
            string result = "";


            for (int i = 0; i < packets.Length; i++)
            {
                if (packets[i].Contains("ICMP"))
                {
                    Match timestamp = Regex.Match(packets[i], "\\d{2}:\\d{2}:\\d{2}\\.\\d{9}");
                    Match addresses = Regex.Match(packets[i], "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d+ > (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\.\\d+");
                    if (!addresses.Success)
                    {
                        addresses = Regex.Match(packets[i], "[0-9a-fA-F]{1,4}:{1,7}[0-9a-fA-F]{1,4} > ([0-9a-fA-F]{1,4}:{1,7}[0-9a-fA-F]{1,4})");
                    }
                    if (timestamp.Success && addresses.Success)
                    {
                        for (int j = 0; j<100; j++)
                        {
                            if (icmp_time[j, 0] == null)
                            {
                                icmp_time[j, 0] = addresses.Groups[1].Value.ToString().Substring(0, (addresses.Groups[1].Value.ToString().Length)-2);
                                icmp_time[j, 1] = timestamp.Value[..7];
                                icmp_time[j, 2] = "1";
                                break;
                            }
                            else if (addresses.Groups[1].Value.ToString().Contains(icmp_time[j, 0]))
                            {
                                if (timestamp.Value.Contains(icmp_time[j, 1]))
                                {
                                    if (icmp_time[j, 2] == null)
                                    {
                                        icmp_time[j, 2] = "1";
                                    }
                                    else
                                    {
                                        icmp_time[j, 2] = (int.Parse(icmp_time[j, 2])+1).ToString();
                                    }
                                    if (int.Parse(icmp_time[j, 2]) >= threshold)
                                    {
                                        result = result + "Possible ICMP ping sweep detected at " + icmp_time[j, 1] + "0";
                                        comp_textblock.Text = result + " from " + icmp_time[0, 0] + "\r\n" + "\r\n" + comp_textblock.Text;
                                        show_notification_icmp();
                                        icmp_time[j, 2] = "0";
                                    }
                                    break;
                                }
                                else
                                {
                                    icmp_time[j, 1] = timestamp.Value[..7];
                                    icmp_time[j, 2] = "1";
                                }
                            }
                        }
                    }
                }
            }
        }

        //############################## BUTTONS AND SWITCHES ###################################

        private void click_button_comp(object sender, RoutedEventArgs e)
        {
            exe_admin("../comp_list.bat");
            string comp_list_string = File.ReadAllText("../comp_list.txt");
            comp_textblock.Text = comp_list_string + "\r\n" + "\r\n" + comp_textblock.Text;
        }

        private void click_button_start(object sender, RoutedEventArgs e)
        {
            exe_admin("../start.bat", ID_textbox.Text);

            Thread.Sleep(500);

            string error = "";
            using (System.IO.FileStream filestream = new System.IO.FileStream("../error_start.txt", System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite))
            {
                using (System.IO.StreamReader streamreader = new System.IO.StreamReader(filestream))
                {
                    error = streamreader.ReadToEnd();
                }
            }
            if (error.StartsWith("Error"))
            {
                comp_textblock.Text = "Please enter a valid network adapter's ID." + "\r\n" + "\r\n" + comp_textblock.Text;
            }
        }

        private void click_button_stop(object sender, RoutedEventArgs e)
        {
            exe_admin("../stop.bat");
        }

        private void switch_on_dos(object sender, RoutedEventArgs e)
        {
            if (dos_switch.IsOn)
            {
                dos_timer.Start();       
            }
            else
            {
                dos_timer.Stop();        
            }
        }

        private void switch_on_mitm(object sender, RoutedEventArgs e)
        {
            if (mitm_switch.IsOn)
            {
                mitm_timer.Start(); 
            }
            else
            {
                mitm_timer.Stop();
            }
        }

        private void switch_on_icmp(object sender, RoutedEventArgs e)
        {
            if (icmp_switch.IsOn)
            {
                icmp_timer.Start();
            }
            else
            {
                icmp_timer.Stop();
            }
        }

        private void click_button_latency(object sender, RoutedEventArgs e)
        {
            LatencyWindow newWindow = new LatencyWindow();
            newWindow.Activate();
        }

        private void click_button_throughput(object sender, RoutedEventArgs e)
        {
            ThroughputWindow newWindow = new ThroughputWindow();
            newWindow.Activate();
        }

        private void click_button_ban_ip(object sender, RoutedEventArgs e)
        {
            exe_admin("../ban_ip.bat", ban_ip_textbox.Text);

            Thread.Sleep(500);

            string error = "";
            using (System.IO.FileStream filestream = new System.IO.FileStream("../error_ban.txt", System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite))
            {
                using (System.IO.StreamReader streamreader = new System.IO.StreamReader(filestream))
                {
                    error = streamreader.ReadToEnd();
                }
            }
            if (error.StartsWith("One") || error.Contains('A'))
            {
                comp_textblock.Text = "Please enter a valid IP address." + "\r\n" + "\r\n" + comp_textblock.Text;
            }
        }

        private void click_button_show_ban_ip(object sender, RoutedEventArgs e)
        {
            exe_admin("../show_ban_ip.bat");
            string result = "";
            string blocked_addresses = File.ReadAllText("../blocked_addresses.txt");
            string[] ip_addresses = blocked_addresses.Split("Monitoring");
            for (int h = 0; h < ip_addresses.Length; h++) {
                Match addresses = Regex.Match(ip_addresses[h], "((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])");
                if (addresses.Success)
                {
                    result = result + addresses.Value + "\t";
                }
            }

            comp_textblock.Text = "List of blocked IP addresses: " + result + "\r\n" + "\r\n" + comp_textblock.Text;
        }

        private void click_button_deban_ip(object sender, RoutedEventArgs e)
        {
            exe_admin("../deban_ip.bat", ban_ip_textbox.Text);

            Thread.Sleep(500);

            string error = "";
            using (System.IO.FileStream filestream = new System.IO.FileStream("../error_deban.txt", System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite))
            {
                using (System.IO.StreamReader streamreader = new System.IO.StreamReader(filestream))
                {
                    error = streamreader.ReadToEnd();
                }
            }
            if (error.Contains("No") || error.Contains('A'))
            {
                comp_textblock.Text = "Please enter a valid IP address." + "\r\n" + "\r\n" + comp_textblock.Text;
            }
        }

    }
}
