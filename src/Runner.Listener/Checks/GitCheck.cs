

using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using GitHub.Runner.Common;
using GitHub.Runner.Sdk;
using GitHub.Services.Common;

namespace GitHub.Runner.Listener
{
    public sealed class GitCheck : RunnerService, ICheckExtension
    {
        private string _logFile = null;
        private string _gitPath = null;

        public int Order => 40;

        public string CheckName => "Git Certificate/Proxy Validation";

        public string CheckDescription => "Make sure the git cli can access to the GitHub Enterprise Server.";

        public string CheckLog => _logFile;

        public string HelpLink => "https://github.com/actions/runner/docs/checks/git.md";

        public Type ExtensionType => typeof(ICheckExtension);

        public override void Initialize(IHostContext hostContext)
        {
            base.Initialize(hostContext);
            _logFile = Path.Combine(HostContext.GetDirectory(WellKnownDirectory.Diag), StringUtil.Format("{0}_{1:yyyyMMdd-HHmmss}-utc.log", nameof(GitCheck), DateTime.UtcNow));
            _gitPath = WhichUtil.Which("git");
        }

        // git access to ghes/gh 
        public async Task<bool> RunCheck(string url, string pat)
        {
            var result = new CheckResult();
            try
            {
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ***************************************************************************************************************");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ****                                                                                                       ****");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ****     Validate server cert and proxy configuration with Git ");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ****                                                                                                       ****");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ***************************************************************************************************************");
                var repoUrlBuilder = new UriBuilder(url);
                repoUrlBuilder.Path = "actions/checkout";
                repoUrlBuilder.UserName = "github";
                repoUrlBuilder.Password = pat;

                var gitProxy = "";
                var proxy = HostContext.WebProxy.GetProxy(repoUrlBuilder.Uri);
                if (proxy != null)
                {
                    if (HostContext.WebProxy.Credentials is NetworkCredential proxyCred)
                    {
                        var proxyUrlWithCred = UrlUtil.GetCredentialEmbeddedUrl(proxy, proxyCred.UserName, proxyCred.Password);
                        gitProxy = $"-c http.proxy={proxyUrlWithCred}";
                    }
                    else
                    {
                        gitProxy = $"-c http.proxy={proxy.AbsoluteUri}";
                    }
                }

                using (var processInvoker = HostContext.CreateService<IProcessInvoker>())
                {
                    processInvoker.OutputDataReceived += new EventHandler<ProcessDataReceivedEventArgs>((sender, args) =>
                    {
                        if (!string.IsNullOrEmpty(args.Data))
                        {
                            result.Logs.Add($"{DateTime.UtcNow.ToString("O")} {args.Data}");
                        }
                    });

                    processInvoker.ErrorDataReceived += new EventHandler<ProcessDataReceivedEventArgs>((sender, args) =>
                    {
                        if (!string.IsNullOrEmpty(args.Data))
                        {
                            result.Logs.Add($"{DateTime.UtcNow.ToString("O")} {args.Data}");
                        }
                    });

                    var gitArgs = $"{gitProxy} ls-remote --exit-code {repoUrlBuilder.Uri.AbsoluteUri} HEAD";
                    result.Logs.Add($"{DateTime.UtcNow.ToString("O")} Run 'git {gitArgs}' ");
                    await processInvoker.ExecuteAsync(HostContext.GetDirectory(WellKnownDirectory.Root), _gitPath, gitArgs, new Dictionary<string, string> { { "GIT_TRACE", "1" }, { "GIT_CURL_VERBOSE", "1" } }, true, CancellationToken.None);
                }

                result.Pass = true;
            }
            catch (Exception ex)
            {
                result.Pass = false;
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} git ls-remote failed with error: {ex}");
            }

            await File.AppendAllLinesAsync(_logFile, result.Logs);
            return result.Pass;
        }
    }
}