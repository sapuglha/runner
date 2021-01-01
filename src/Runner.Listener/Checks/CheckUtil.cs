using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using GitHub.Runner.Common;
using GitHub.Services.Common;

namespace GitHub.Runner.Listener.Check
{
    public static class CheckUtil
    {
        public static async Task<CheckResult> CheckDns(string targetUrl)
        {
            var result = new CheckResult();
            var url = new Uri(targetUrl);
            try
            {
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ***************************************************************************************************************");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ****                                                                                                       ****");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ****     Try DNS lookup for {url.Host} ");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ****                                                                                                       ****");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ***************************************************************************************************************");
                IPHostEntry host = await Dns.GetHostEntryAsync(url.Host);
                foreach (var address in host.AddressList)
                {
                    result.Logs.Add($"{DateTime.UtcNow.ToString("O")} Resolved DNS for {url.Host} to '{address}'");
                }

                result.Pass = true;
            }
            catch (Exception ex)
            {
                result.Pass = false;
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} Resolved DNS for {url.Host} failed with error: {ex}");
            }

            return result;
        }

        public static async Task<CheckResult> CheckPing(string targetUrl)
        {
            var result = new CheckResult();
            var url = new Uri(targetUrl);
            try
            {
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ***************************************************************************************************************");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ****                                                                                                       ****");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ****     Try ping {url.Host} ");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ****                                                                                                       ****");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ***************************************************************************************************************");
                using (var ping = new Ping())
                {
                    var reply = await ping.SendPingAsync(url.Host);
                    if (reply.Status == IPStatus.Success)
                    {
                        result.Pass = true;
                        result.Logs.Add($"{DateTime.UtcNow.ToString("O")} Ping {url.Host} ({reply.Address}) succeed within to '{reply.RoundtripTime} ms'");
                    }
                    else
                    {
                        result.Pass = false;
                        result.Logs.Add($"{DateTime.UtcNow.ToString("O")} Ping {url.Host} ({reply.Address}) failed with '{reply.Status}'");
                    }
                }
            }
            catch (Exception ex)
            {
                result.Pass = false;
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} Ping api.github.com failed with error: {ex}");
            }

            return result;
        }

        public static async Task<CheckResult> CheckHttpsRequests(this IHostContext hostContext, string url, string expectedHeader)
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
                using (var httpClientHandler = hostContext.CreateHttpClientHandler())
                using (var httpClient = new HttpClient(httpClientHandler))
                {
                    httpClient.DefaultRequestHeaders.UserAgent.AddRange(hostContext.UserAgents);
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

    public sealed class HttpEventSourceListener : EventListener
    {
        private readonly List<string> _logs;
        private readonly object _lock = new object();
        private readonly Dictionary<string, HashSet<string>> _ignoredEvent = new Dictionary<string, HashSet<string>>
        {
            {
                "Private.InternalDiagnostics.System.Net.Http",
                new HashSet<string>
                {
                    "Info",
                    "Associate"
                }
            },
            {
                "Private.InternalDiagnostics.System.Net.Security",
                new HashSet<string>
                {
                    "Info",
                    "SslStreamCtor",
                    "SecureChannelCtor",
                    "NoDelegateNoClientCert",
                    "CertsAfterFiltering",
                    "UsingCachedCredential",
                    "SspiSelectedCipherSuite"
                }
            }
        };

        public HttpEventSourceListener(List<string> logs)
        {
            _logs = logs;
            if (Environment.GetEnvironmentVariable("ACTIONS_RUNNER_TRACE_ALL_HTTP_EVENT") == "1")
            {
                _ignoredEvent.Clear();
            }
        }

        protected override void OnEventSourceCreated(EventSource eventSource)
        {
            base.OnEventSourceCreated(eventSource);

            if (eventSource.Name == "Private.InternalDiagnostics.System.Net.Http" ||
                eventSource.Name == "Private.InternalDiagnostics.System.Net.Security")
            {
                EnableEvents(eventSource, EventLevel.Informational, EventKeywords.All);
            }
        }

        protected override void OnEventWritten(EventWrittenEventArgs eventData)
        {
            base.OnEventWritten(eventData);
            lock (_lock)
            {
                if (_ignoredEvent.TryGetValue(eventData.EventSource.Name, out var ignored) &&
                    ignored.Contains(eventData.EventName))
                {
                    return;
                }

                _logs.Add($"{DateTime.UtcNow.ToString("O")} [START {eventData.EventSource.Name} - {eventData.EventName}]");
                _logs.AddRange(eventData.Payload.Select(x => string.Join(Environment.NewLine, x.ToString().Split(Environment.NewLine).Select(y => $"{DateTime.UtcNow.ToString("O")} {y}"))));
                _logs.Add($"{DateTime.UtcNow.ToString("O")} [END {eventData.EventSource.Name} - {eventData.EventName}]");
            }
        }
    }
}