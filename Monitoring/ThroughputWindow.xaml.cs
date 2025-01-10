using Microsoft.UI.Xaml;
using System;
using System.IO;
using System.Text.RegularExpressions;


namespace Monitoring
{
    public partial class ThroughputWindow : Window
    {
        private DispatcherTimer throughput_timer;
        long throughput_position = 0;
        string result = "";
        string[] throughput = new string[1000];
        int[,] throughput_where = new int[100, 100];
        string time = "none";

        public ThroughputWindow()
        {
            this.InitializeComponent();
            Title = "Throughput";
            setup_timer();
            throughput_timer.Start();
        }

        private void setup_timer()
        {
            throughput_timer = new DispatcherTimer();
            throughput_timer.Interval = TimeSpan.FromSeconds(5);
            throughput_timer.Tick += latency_timer_tick;
        }

        private void latency_timer_tick(object sender, object e)
        {
            calculate_throughput("../Captures/capture.txt");
        }

        public void calculate_throughput(string file)
        {
            string text = "";
            using (System.IO.FileStream filestream = new System.IO.FileStream(file, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite))
            {
                filestream.Seek(throughput_position, SeekOrigin.Begin);
                using (System.IO.StreamReader streamreader = new System.IO.StreamReader(filestream))
                {
                    text = streamreader.ReadToEnd();
                    throughput_position = filestream.Position;
                }
            }

            string[] packets = text.Split("\t");
            decimal total_length = 0;
            string[] times = new string[1000];

            for (int i = packets.Length - 1; i > 0; i--)
            {
                Match timestamp = Regex.Match(packets[i], "(\\d{2}):(\\d{2}):(\\d{2})\\.(\\d{9})");
                Match length = Regex.Match(packets[i], "length\\s(\\d+):");

                if (timestamp.Success && length.Success)
                {
                    if (time == "none")
                    {
                        time = timestamp.Value;
                    }
                    if (!timestamp.Value.Contains(time[..8]))
                    {
                        result = result + "\r\n" + time[..8] + ":   " + (total_length.ToString()) + " bytes/second";
                        throughput_textblock.Text = result + " ";
                        total_length = 0;
                        time = timestamp.Value;
                    }
                    if (timestamp.Value.Contains(time[..8]))
                    {
                        total_length = total_length + decimal.Parse(length.Groups[1].Value);
                    }
                }
            }
        }
    }
}