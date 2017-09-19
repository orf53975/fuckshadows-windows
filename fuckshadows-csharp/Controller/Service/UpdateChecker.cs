using System;
using System.Collections.Generic;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Fuckshadows.Model;
using Fuckshadows.Util;
using Fuckshadows.Util.Sockets;
using Newtonsoft.Json.Linq;

namespace Fuckshadows.Controller
{
    public class UpdateChecker
    {
        private const string UpdateURL = "https://api.github.com/repos/shadowsocks/shadowsocks-windows/releases";

        private const string UserAgent =
            "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36";

        private Configuration _config;
        public bool NewVersionFound;
        public string LatestVersionNumber;
        public string LatestVersionSuffix;
        private string _latestVersionName;
        private string _latestVersionUrl;
        public string LatestVersionLocalName;
        public event EventHandler CheckUpdateCompleted;

        public const string Version = "30.0";

        public async Task CheckUpdate(Configuration config, TimeSpan span)
        {
            await Task.Delay(span);
            Task.Factory.StartNew(async () => await CheckUpdate(config)).Forget();
        }

        public async Task CheckUpdate(Configuration config)
        {
            this._config = config;

            Logging.Debug("Checking updates...");
            try
            {
                var response = await WebClientDownloadStringTaskAsync(UpdateURL);

                JArray result = JArray.Parse(response);

                List<Asset> asserts = new List<Asset>();
                if (result != null)
                {
                    foreach (JObject release in result)
                    {
                        var isPreRelease = (bool) release["prerelease"];
                        if (isPreRelease && !config.checkPreRelease)
                        {
                            continue;
                        }
                        foreach (JObject asset in (JArray) release["assets"])
                        {
                            Asset ass = Asset.ParseAsset(asset);
                            if (ass != null)
                            {
                                ass.prerelease = isPreRelease;
                                if (ass.IsNewVersion(Version, config.checkPreRelease))
                                {
                                    asserts.Add(ass);
                                }
                            }
                        }
                    }
                }
                if (asserts.Count != 0)
                {
                    SortByVersions(asserts);
                    Asset asset = asserts[asserts.Count - 1];
                    NewVersionFound = true;
                    _latestVersionUrl = asset.browser_download_url;
                    LatestVersionNumber = asset.version;
                    _latestVersionName = asset.name;
                    LatestVersionSuffix = asset.suffix == null ? "" : $"-{asset.suffix}";

                    Task.Factory.StartNew(async () => await StartDownload()).Forget();
                }
                else
                {
                    Logging.Debug("No update is available");
                    CheckUpdateCompleted?.Invoke(this, new EventArgs());
                }
            }
            catch (Exception e)
            {
                Logging.LogUsefulException(e);
            }
        }

        private Task<string> WebClientDownloadStringTaskAsync(string url)
        {
            var tcs = new TaskCompletionSource<string>();
            var wc = CreateWebClient();
            wc.DownloadStringCompleted += (s, e) =>
            {
                if (e.Error != null)
                    tcs.TrySetException(e.Error);
                else if (e.Cancelled)
                    tcs.TrySetCanceled();
                else
                    tcs.TrySetResult(e.Result);
            };
            wc.DownloadStringAsync(new Uri(url));
            return tcs.Task;
        }

        private Task<bool> WebClientDownloadFileTaskAsync()
        {
            LatestVersionLocalName = Utils.GetTempPath(_latestVersionName);
            var tcs = new TaskCompletionSource<bool>();
            var wc = CreateWebClient();
            wc.DownloadFileCompleted += (s, e) =>
            {
                if (e.Error != null)
                    tcs.TrySetException(e.Error);
                else if (e.Cancelled)
                    tcs.TrySetCanceled();
                else
                    tcs.TrySetResult(true);
            };
            wc.DownloadFileAsync(new Uri(_latestVersionUrl), LatestVersionLocalName);
            return tcs.Task;
        }

        private async Task StartDownload()
        {
            try
            {
                if (!await WebClientDownloadFileTaskAsync()) return;

                Logging.Debug(
                    $"New version {LatestVersionNumber}{LatestVersionSuffix} found: {LatestVersionLocalName}");
                CheckUpdateCompleted?.Invoke(this, new EventArgs());
            }
            catch (Exception ex)
            {
                Logging.LogUsefulException(ex);
            }
        }

        private WebClient CreateWebClient()
        {
            WebClient http = new WebClient();
            http.Headers.Add("User-Agent", UserAgent);
            http.Proxy = new WebProxy(IPAddress.Loopback.ToString(), _config.localPort);
            return http;
        }

        private void SortByVersions(List<Asset> asserts)
        {
            asserts.Sort();
        }

        public class Asset : IComparable<Asset>
        {
            public bool prerelease;
            public string name;
            public string version;
            public string browser_download_url;
            public string suffix;

            public static Asset ParseAsset(JObject assertJObject)
            {
                var name = (string) assertJObject["name"];
                Match match = Regex.Match(name, @"^Shadowsocks-(?<version>\d+(?:\.\d+)*)(?:|-(?<suffix>.+))\.\w+$",
                    RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    string version = match.Groups["version"].Value;

                    var asset = new Asset
                    {
                        browser_download_url = (string) assertJObject["browser_download_url"],
                        name = name,
                        version = version
                    };

                    if (match.Groups["suffix"].Success)
                    {
                        asset.suffix = match.Groups["suffix"].Value;
                    }

                    return asset;
                }

                return null;
            }

            public bool IsNewVersion(string currentVersion, bool checkPreRelease)
            {
                if (prerelease && !checkPreRelease)
                {
                    return false;
                }
                if (version == null)
                {
                    return false;
                }
                var cmp = CompareVersion(version, currentVersion);
                return cmp > 0;
            }

            public static int CompareVersion(string l, string r)
            {
                var ls = l.Split('.');
                var rs = r.Split('.');
                for (int i = 0; i < Math.Max(ls.Length, rs.Length); i++)
                {
                    int lp = (i < ls.Length) ? int.Parse(ls[i]) : 0;
                    int rp = (i < rs.Length) ? int.Parse(rs[i]) : 0;
                    if (lp != rp)
                    {
                        return lp - rp;
                    }
                }
                return 0;
            }

            public int CompareTo(Asset other)
            {
                return CompareVersion(version, other.version);
            }
        }
    }
}