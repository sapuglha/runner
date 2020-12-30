

using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;
using GitHub.Runner.Common;
using GitHub.Runner.Sdk;
using GitHub.Services.Common;

namespace GitHub.Runner.Listener
{
    public sealed class GhesCheck : RunnerService, ICheckExtension
    {
        private string _logFile = "";

        public int Order => 20;

        public string CheckName => "GHES Connection";

        public string CheckDescription => "Make sure the actions runner have access to the GitHub Enterprise Server.";

        public string CheckLog => _logFile;

        public string HelpLink => "https://github.com/actions/runner/docs/checks/ghesconnection.md";

        public Type ExtensionType => typeof(ICheckExtension);

        public override void Initialize(IHostContext hostContext)
        {
            base.Initialize(hostContext);
            _logFile = Path.Combine(HostContext.GetDirectory(WellKnownDirectory.Diag), StringUtil.Format("{0}_{1:yyyyMMdd-HHmmss}-utc.log", nameof(GhesCheck), DateTime.UtcNow));
        }

        // 1. runner access to github.com (dns->ping->pwsh->curl->openssl)
        public async Task<bool> RunCheck(string url, string pat)
        {
            var result = true;
            var checkTasks = new List<Task<CheckResult>>();
            checkTasks.Add(CheckGitHubDns());
            checkTasks.Add(PingGitHub());
            checkTasks.Add(CheckHttpsRequests("https://api.github.com", "X-GitHub-Request-Id"));
            checkTasks.Add(CheckHttpsRequests("https://pipelines.actions.githubusercontent.com/_apis/health", "x-vss-e2eid"));
            checkTasks.Add(CheckHttpsRequests("https://vstoken.actions.githubusercontent.com/_apis/health", "x-vss-e2eid"));

            while (checkTasks.Count > 0)
            {
                var finishedCheckTask = await Task.WhenAny<CheckResult>(checkTasks);
                var finishedCheck = await finishedCheckTask;
                result = result && finishedCheck.Pass;
                await File.AppendAllLinesAsync(_logFile, finishedCheck.Logs);
                checkTasks.Remove(finishedCheckTask);
            }

            await Task.WhenAll(checkTasks);
            return result;
        }

        private async Task<CheckResult> CheckGitHubDns()
        {
            var result = new CheckResult();
            try
            {
                IPHostEntry host = await Dns.GetHostEntryAsync("github.com");
                foreach (var address in host.AddressList)
                {
                    result.Logs.Add($"Resolved DNS for github.com to '{address}'");
                }

                result.Pass = true;
            }
            catch (Exception ex)
            {
                result.Pass = false;
                result.Logs.Add($"Resolved DNS for github.com failed with error: {ex}");
            }

            return result;
        }

        private async Task<CheckResult> PingGitHub()
        {
            var result = new CheckResult();
            try
            {
                using (var ping = new Ping())
                {
                    var reply = await ping.SendPingAsync("github.com");
                    if (reply.Status == IPStatus.Success)
                    {
                        result.Pass = true;
                        result.Logs.Add($"Ping github.com ({reply.Address}) succeed within to '{reply.RoundtripTime} ms'");
                    }
                    else
                    {
                        result.Pass = false;
                        result.Logs.Add($"Ping github.com ({reply.Address}) failed with '{reply.Status}'");
                    }
                }
            }
            catch (Exception ex)
            {
                result.Pass = false;
                result.Logs.Add($"Resolved DNS for github.com failed with error: {ex}");
            }

            return result;
        }

        private async Task<CheckResult> CheckHttpsRequests(string url, string expectedHeader)
        {
            var result = new CheckResult();
            try
            {
                result.Logs.Add("***************************************************************************************************************");
                result.Logs.Add("****                                                                                                       ****");
                result.Logs.Add($"****     Send HTTPS Request to {url} ");
                result.Logs.Add("****                                                                                                       ****");
                result.Logs.Add("***************************************************************************************************************");
                using (var _ = new HttpEventSourceListener(result.Logs))
                using (var httpClientHandler = HostContext.CreateHttpClientHandler())
                using (var httpClient = new HttpClient(httpClientHandler))
                {
                    httpClient.DefaultRequestHeaders.UserAgent.AddRange(HostContext.UserAgents);
                    var response = await httpClient.GetAsync(url);

                    result.Logs.Add(response.StatusCode.ToString());
                    result.Logs.Add(response.Headers.ToString());
                    result.Logs.Add(await response.Content.ReadAsStringAsync());
                    if (response.IsSuccessStatusCode)
                    {
                        if (response.Headers.Contains(expectedHeader))
                        {
                            result.Pass = true;
                            result.Logs.Add("***************************************************************************************************************");
                            result.Logs.Add($"Http request 'GET' to {url} succeed");
                            result.Logs.Add("***************************************************************************************************************");
                            result.Logs.Add("");
                            result.Logs.Add("");
                        }
                        else
                        {
                            result.Pass = false;
                            result.Logs.Add("***************************************************************************************************************");
                            result.Logs.Add($"Http request 'GET' to {url} succeed but doesn't have expected HTTP Header.");
                            result.Logs.Add("***************************************************************************************************************");
                            result.Logs.Add("");
                            result.Logs.Add("");
                        }
                    }
                    else
                    {
                        result.Pass = false;
                        result.Logs.Add("***************************************************************************************************************");
                        result.Logs.Add($"Http request 'GET' to https://api.github.com failed with {response.StatusCode}");
                        result.Logs.Add("***************************************************************************************************************");
                        result.Logs.Add("");
                        result.Logs.Add("");
                    }
                }
            }
            catch (Exception ex)
            {
                result.Pass = false;
                result.Logs.Add("***************************************************************************************************************");
                result.Logs.Add($"Make Https request to github.com failed with error: {ex}");
                result.Logs.Add("***************************************************************************************************************");
                result.Logs.Add("");
                result.Logs.Add("");
            }
            return result;
        }
    }
}