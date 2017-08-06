using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Fuckshadows.Model;
using Fuckshadows.Properties;
using Fuckshadows.Util;
using Newtonsoft.Json;

namespace Fuckshadows.Controller
{
    public class GFWListUpdater
    {
        private const string GFWLIST_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt";

        public event EventHandler<ResultEventArgs> UpdateCompleted;

        public event ErrorEventHandler Error;

        public class ResultEventArgs : EventArgs
        {
            public readonly bool Success;

            public ResultEventArgs(bool success)
            {
                this.Success = success;
            }
        }

        private static readonly IEnumerable<char> IgnoredLineBegins = new[] { '!', '[' };

        public async Task UpdatePACFromGFWList(Configuration config)
        {
            try
            {
                var result = await WebClientDownloadStringTaskAsync(config);
                File.WriteAllText(Utils.GetTempPath("gfwlist.txt"), result, Encoding.UTF8);
                List<string> lines = ParseResult(result);
                if (File.Exists(PACServer.USER_RULE_FILE))
                {
                    string local = FileManager.NonExclusiveReadAllText(PACServer.USER_RULE_FILE, Encoding.UTF8);
                    using (var sr = new StringReader(local))
                    {
                        foreach (var rule in sr.NonWhiteSpaceLines())
                        {
                            if (rule.BeginWithAny(IgnoredLineBegins))
                                continue;
                            lines.Add(rule);
                        }
                    }
                }
                string abpContent = File.Exists(PACServer.USER_ABP_FILE)
                    ? FileManager.NonExclusiveReadAllText(PACServer.USER_ABP_FILE, Encoding.UTF8)
                    : Utils.UnGzip(Resources.abp_js);
                abpContent = abpContent.Replace("__RULES__", JsonConvert.SerializeObject(lines, Formatting.Indented));
                if (File.Exists(PACServer.PAC_FILE))
                {
                    string original = FileManager.NonExclusiveReadAllText(PACServer.PAC_FILE, Encoding.UTF8);
                    if (original == abpContent)
                    {
                        UpdateCompleted?.Invoke(this, new ResultEventArgs(false));
                        return;
                    }
                }
                File.WriteAllText(PACServer.PAC_FILE, abpContent, Encoding.UTF8);
                UpdateCompleted?.Invoke(this, new ResultEventArgs(true));
            }
            catch (Exception ex)
            {
                Error?.Invoke(this, new ErrorEventArgs(ex));
            }
        }

        private static Task<string> WebClientDownloadStringTaskAsync(Configuration config)
        {
            var tcs = new TaskCompletionSource<string>();
            var wc = new WebClient();
            wc.DownloadStringCompleted += (s, e) =>
            {
                if (e.Error != null)
                    tcs.TrySetException(e.Error);
                else if (e.Cancelled)
                    tcs.TrySetCanceled();
                else
                    tcs.TrySetResult(e.Result);
            };
            wc.Proxy = new WebProxy(IPAddress.Loopback.ToString(), config.localPort);
            wc.DownloadStringAsync(new Uri(GFWLIST_URL));
            return tcs.Task;
        }

        public static List<string> ParseResult(string response)
        {
            byte[] bytes = Convert.FromBase64String(response);
            string content = Encoding.ASCII.GetString(bytes);
            List<string> valid_lines = new List<string>();
            using (var sr = new StringReader(content))
            {
                foreach (var line in sr.NonWhiteSpaceLines())
                {
                    if (line.BeginWithAny(IgnoredLineBegins))
                        continue;
                    valid_lines.Add(line);
                }
            }
            return valid_lines;
        }
    }
}
