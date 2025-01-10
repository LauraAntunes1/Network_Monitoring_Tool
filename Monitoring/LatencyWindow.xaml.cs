using Microsoft.UI.Xaml;
using System;
using System.IO;
using System.Text.RegularExpressions;

namespace Monitoring
{
    public partial class LatencyWindow : Window
    {
        long latency_time_milliseconds = 0;
        long latency_time = 0;
        int[,] latency_where = new int[100, 100];
        string[,,,] latency_rtts = new string[100, 100, 20, 4];
        private DispatcherTimer latency_timer;
        long latency_position = 0;
        string latency_result = "";

        public LatencyWindow()
        {
            this.InitializeComponent();
            Title = "Latency";
            setup_timer();
            latency_timer.Start();
        }

        private void setup_timer()
        {
            latency_timer = new DispatcherTimer();
            latency_timer.Interval = TimeSpan.FromSeconds(5);
            latency_timer.Tick += latency_timer_tick;
        }

        private void latency_timer_tick(object sender, object e)
        {
            calculate_rtt("../Captures/capture.txt");
        }

        public void calculate_rtt(string file)
        {
            string text = "";
            using (System.IO.FileStream filestream = new System.IO.FileStream(file, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite))
            {
                filestream.Seek(latency_position, SeekOrigin.Begin);
                using (System.IO.StreamReader streamreader = new System.IO.StreamReader(filestream))
                {
                    text = streamreader.ReadToEnd();
                    latency_position = filestream.Position;
                }
            }

            string[] packets = text.Split("\t");
            string all_times = "";
            string last_time = "";
            string adds = null;

            for (int i = 0; i < packets.Length; i++)
            {
                if (packets[i].Contains("Flags [S]"))
                {
                    Match timestamp = Regex.Match(packets[i], "(\\d{2}):(\\d{2}):(\\d{2})\\.(\\d{9})");
                    Match addresses = Regex.Match(packets[i], "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d+) > (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d+)");
                    Match sequence = Regex.Match(packets[i], "seq (\\d+)");
                    if (timestamp.Success && addresses.Success && sequence.Success)
                    {
                        adds = addresses.Value + ": ";
                        latency_time_milliseconds = long.Parse(timestamp.Groups[4].Value);
                        latency_time = long.Parse(timestamp.Groups[1].Value) * 60 * 60 + long.Parse(timestamp.Groups[2].Value) * 60 + long.Parse(timestamp.Groups[3].Value);

                        for (int b = 0; b < 100; b++)
                        {
                            if (latency_rtts[0, b, 0, 0] == null)
                            {
                                latency_rtts[0, b, 0, 0] = addresses.Groups[1].Value;
                            }
                            if (latency_rtts[0, b, 0, 0].Equals(addresses.Groups[1].Value))
                            {
                                for (int c = 0; c < 100; c++)
                                {
                                    if (latency_rtts[c, 0, 0, 0] == null)
                                    {
                                        latency_rtts[c, 0, 0, 0] = addresses.Groups[2].Value;
                                    }
                                    if (latency_rtts[c, 0, 0, 0].Equals(addresses.Groups[2].Value))
                                    {
                                        latency_rtts[c, b, 0, 3] = sequence.Groups[1].Value;
                                        latency_rtts[c, b, 0, 1] = latency_time.ToString();
                                        latency_rtts[c, b, 0, 2] = latency_time_milliseconds.ToString();
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
                            if (latency_rtts[0, b, 0, 0].Equals(addresses.Groups[2].Value))
                            {
                                for (int c = 0; c < 100; c++)
                                {
                                    if (latency_rtts[c, 0, 0, 0].Equals(addresses.Groups[1].Value))
                                    {
                                        if (latency_rtts[c, b, 0, 3].Equals((long.Parse(ack.Groups[1].Value) - 1).ToString()))
                                        {
                                            all_times = "";
                                            for (int d = 1; d < 20; d++)
                                            {
                                                if (latency_rtts[c, b, d, 0] != null)
                                                {
                                                    all_times = all_times + "   " + double.Parse(latency_rtts[c, b, d, 0]);
                                                    if (d == 19)
                                                    {
                                                        latency_rtts[c, b, latency_where[c, b], 0] = (decimal.Parse((long.Parse(timestamp.Groups[1].Value) * 60 * 60 + long.Parse(timestamp.Groups[2].Value) * 60 + long.Parse(timestamp.Groups[3].Value)).ToString() + "." + timestamp.Groups[4].Value) - decimal.Parse(latency_rtts[c, b, 0, 1] + "." + latency_rtts[c, b, 0, 2])).ToString();
                                                        last_time = latency_rtts[c, b, latency_where[c, b], 0];
                                                        if (latency_where[c, b] < 19)
                                                        {
                                                            latency_where[c, b]++;
                                                        }
                                                        else
                                                        {
                                                            latency_where[c, b] = 1;
                                                        }
                                                        break;
                                                    }
                                                }
                                                else
                                                {
                                                    latency_rtts[c, b, d, 0] = (decimal.Parse((long.Parse(timestamp.Groups[1].Value) * 60 * 60 + long.Parse(timestamp.Groups[2].Value) * 60 + long.Parse(timestamp.Groups[3].Value)).ToString() + "." + timestamp.Groups[4].Value) - decimal.Parse(latency_rtts[c, b, 0, 1] + "." + latency_rtts[c, b, 0, 2])).ToString();
                                                    last_time = latency_rtts[c, b, d, 0];
                                                    break;
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
                if (adds != null)
                {
                    latency_result = "\r\n" + adds + all_times + "   " + last_time + "\r\n" + latency_result;
                    adds = null;
                }
                latency_textblock.Text = latency_result;
            }
        }

    }
}