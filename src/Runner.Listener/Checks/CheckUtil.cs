using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.Linq;

namespace GitHub.Runner.Listener
{
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