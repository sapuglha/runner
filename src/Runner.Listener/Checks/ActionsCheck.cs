using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using GitHub.Runner.Common;
using GitHub.Runner.Sdk;
using GitHub.Services.Common;

namespace GitHub.Runner.Listener
{
    public sealed class ActionsCheck : RunnerService, ICheckExtension
    {
        private string _logFile = "";

        public int Order => 20;

        public string CheckName => "GitHub Actions Connection";

        public string CheckDescription => "Make sure the actions runner have access to the Actions Service in GitHub or GitHub Enterprise Server.";

        public string CheckLog => _logFile;

        public string HelpLink => "https://github.com/actions/runner/docs/checks/actionsconnection.md";

        public Type ExtensionType => typeof(ICheckExtension);

        public override void Initialize(IHostContext hostContext)
        {
            base.Initialize(hostContext);
            _logFile = Path.Combine(HostContext.GetDirectory(WellKnownDirectory.Diag), StringUtil.Format("{0}_{1:yyyyMMdd-HHmmss}-utc.log", nameof(ActionsCheck), DateTime.UtcNow));
        }

        // runner access to actions service
        public async Task<bool> RunCheck(string url, string pat)
        {
            var result = true;
            var checkTasks = new List<Task<CheckResult>>();

            string githubApiUrl = null;
            string actionsTokenServiceUrl = null;
            string actionsPipelinesServiceUrl = null;
            var urlBuilder = new UriBuilder(url);
            if (UrlUtil.IsHostedServer(urlBuilder))
            {
                urlBuilder.Host = $"api.{urlBuilder.Host}";
                urlBuilder.Path = "";
                githubApiUrl = urlBuilder.Uri.AbsoluteUri;
                actionsTokenServiceUrl = "https://vstoken.actions.githubusercontent.com/_apis/health";
                actionsPipelinesServiceUrl = "https://pipelines.actions.githubusercontent.com/_apis/health";
            }
            else
            {
                urlBuilder.Path = "api/v3";
                githubApiUrl = urlBuilder.Uri.AbsoluteUri;
                urlBuilder.Path = "_services/vstoken/_apis/health";
                actionsTokenServiceUrl = urlBuilder.Uri.AbsoluteUri;
                urlBuilder.Path = "_services/pipelines/_apis/health";
                actionsPipelinesServiceUrl = urlBuilder.Uri.AbsoluteUri;
            }

            checkTasks.Add(CheckHttpsRequests(githubApiUrl, "X-GitHub-Request-Id"));
            checkTasks.Add(CheckHttpsRequests(actionsTokenServiceUrl, "x-vss-e2eid"));
            checkTasks.Add(CheckHttpsRequests(actionsPipelinesServiceUrl, "x-vss-e2eid"));

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

        private async Task<CheckResult> CheckHttpsRequests(string url, string expectedHeader)
        {
            var result = new CheckResult();
            try
            {
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ***************************************************************************************************************");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ****                                                                                                       ****");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ****     Send HTTPS Request to {url} ");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ****                                                                                                       ****");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ***************************************************************************************************************");
                using (var _ = new HttpEventSourceListener(result.Logs))
                using (var httpClientHandler = HostContext.CreateHttpClientHandler())
                using (var httpClient = new HttpClient(httpClientHandler))
                {
                    httpClient.DefaultRequestHeaders.UserAgent.AddRange(HostContext.UserAgents);
                    var response = await httpClient.GetAsync(url);

                    result.Logs.Add($"{DateTime.UtcNow.ToString("O")} Http status code: {response.StatusCode}");
                    result.Logs.Add($"{DateTime.UtcNow.ToString("O")} Http response headers: {response.Headers}");

                    var responseContent = await response.Content.ReadAsStringAsync();
                    result.Logs.Add($"{DateTime.UtcNow.ToString("O")} Http response body: {responseContent}");
                    if (response.IsSuccessStatusCode)
                    {
                        if (response.Headers.Contains(expectedHeader))
                        {
                            result.Pass = true;
                            result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ***************************************************************************************************************");
                            result.Logs.Add($"{DateTime.UtcNow.ToString("O")} Http request 'GET' to {url} succeed");
                            result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ***************************************************************************************************************");
                            result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ");
                            result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ");
                        }
                        else
                        {
                            result.Pass = false;
                            result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ***************************************************************************************************************");
                            result.Logs.Add($"{DateTime.UtcNow.ToString("O")} Http request 'GET' to {url} succeed but doesn't have expected HTTP Header.");
                            result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ***************************************************************************************************************");
                            result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ");
                            result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ");
                        }
                    }
                    else
                    {
                        result.Pass = false;
                        result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ***************************************************************************************************************");
                        result.Logs.Add($"{DateTime.UtcNow.ToString("O")} Http request 'GET' to {url} failed with {response.StatusCode}");
                        result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ***************************************************************************************************************");
                        result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ");
                        result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ");
                    }
                }
            }
            catch (Exception ex)
            {
                result.Pass = false;
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ***************************************************************************************************************");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} Https request 'GET' to {url} failed with error: {ex}");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ***************************************************************************************************************");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ");
            }

            return result;
        }
    }
}