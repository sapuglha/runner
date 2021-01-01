

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using GitHub.Runner.Common;
using GitHub.Runner.Sdk;

namespace GitHub.Runner.Listener.Check
{
    public sealed class NodeJsCheck : RunnerService, ICheckExtension
    {
        private const string _nodejsScript = @"
const https = require('https')
const options = {
  hostname: '<HOSTNAME>',
  port: <PORT>,
  path: '/',
  method: 'GET',
  headers: { 'User-Agent': 'GitHubActionsRunnerCheck/1.0' }
}
const req = https.request(options, res => {
  console.log(`statusCode: ${res.statusCode}`)
  console.log(`headers: ${JSON.stringify(res.headers)}`)

  res.on('data', d => {
    process.stdout.write(d)
  })
})
req.on('error', error => {
  console.error(error)
})
req.end()
";

        private const string _nodejsCertScript = @"
const https = require('https')
const fs = require('fs')
const options = {
    hostname: '<HOSTNAME>',
    port: <PORT>,
    path: '/',
    method: 'GET',
    headers: { 'User-Agent': 'GitHubActionsRunnerCheck/1.0' },
    rejectUnauthorized: false
}
const req = https.request(options, res => {
    console.log(`statusCode: ${res.statusCode}`)
    console.log(`headers: ${JSON.stringify(res.headers)}`)
    let cert = socket.getPeerCertificate(true)
    let certPEM = ''
    let fingerprints = {}
    while (cert != null && fingerprints[cert.fingerprint] != '1') {
        fingerprints[cert.fingerprint] = '1'
        certPEM = certPEM + '-----BEGIN CERTIFICATE-----\n'
        let certEncoded = cert.raw.toString('base64')
        for (let i = 0; i < certEncoded.length; i++) {
            certPEM = certPEM + certEncoded[i]
            if (i != certEncoded.length - 1 && (i + 1) % 64 == 0) {
                certPEM = certPEM + '\n'
            }
        }
        certPEM = certPEM + '\n-----END CERTIFICATE-----\n'
        cert = cert.issuerCertificate
    }
    console.log(certPEM)
    fs.writeFileSync('./cacert.pem', certPEM)
    res.on('data', d => {
        process.stdout.write(d)
    })
})
req.on('error', error => {
  console.error(error)
})
req.end()
";

        private const string _nodejsWithProxyScript = @"
const http = require('http')
const https = require('https')
const hostname = '<HOSTNAME>'
const port = '<PORT>'
const proxyHost = '<PROXYHOST>'
const proxyPort = '<PROXYPORT>'
const username = '<PROXYUSERNAME>'
const password = '<PROXYPASSWORD>'
const auth = 'Basic ' + Buffer.from(username + ':' + password).toString('base64')

const options = {
    hostname: proxyHost,
    port: proxyPort,
    method: 'CONNECT',
    path: `${hostname}:${port}`
}

if (username != '' || password != '') {
    options.headers = {
        'Proxy-Authorization': auth,
    }
}
http.request(options).on('connect', (res, socket) => {
    if (res.statusCode === 200) {
        https.get({
            host: hostname,
            port: port,
            socket: socket,
            agent: false,
            path: '/',
            headers: {
                'User-Agent': 'GitHubActionsRunnerCheck/1.0'
            }
        }, (res) => {
            let chunks = []
            res.on('data', chunk => chunks.push(chunk))
            res.on('end', () => {
                console.log('DONE', Buffer.concat(chunks).toString('utf8'))
            })
        })
    }
}).on('error', (err) => {
    console.error('error', err)
}).end()
";

        private const string _nodejsCertWithProxyScript = @"
const http = require('http')
const https = require('https')
const fs = require('fs')
const hostname = '<HOSTNAME>'
const port = '<PORT>'
const proxyHost = '<PROXYHOST>'
const proxyPort = '<PROXYPORT>'
const username = '<PROXYUSERNAME>'
const password = '<PROXYPASSWORD>'
const auth = 'Basic ' + Buffer.from(username + ':' + password).toString('base64')

const options = {
    host: proxyHost,
    port: proxyPort,
    method: 'CONNECT',
    path: `${hostname}:${port}`,
}

if (username != '' || password != '') {
    options.headers = {
        'Proxy-Authorization': auth,
    }
}

process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0'

http.request(options).on('connect', (res, socket) => {
    if (res.statusCode === 200) {
        https.get({
            host: hostname,
            port: port,
            socket: socket,
            agent: false,
            path: '/',
            headers: {
                'User-Agent': 'GitHubActionsRunnerCheck/1.0'
            }
        }, (res) => {
            let cert = res.socket.getPeerCertificate(true)
            let certPEM = ''
            let fingerprints = {}
            while (cert != null && fingerprints[cert.fingerprint] != '1') {
                fingerprints[cert.fingerprint] = '1'
                certPEM = certPEM + '-----BEGIN CERTIFICATE-----\n'
                let certEncoded = cert.raw.toString('base64')
                for (let i = 0; i < certEncoded.length; i++) {
                    certPEM = certPEM + certEncoded[i]
                    if (i != certEncoded.length - 1 && (i + 1) % 64 == 0) {
                        certPEM = certPEM + '\n'
                    }
                }
                certPEM = certPEM + '\n-----END CERTIFICATE-----\n'
                cert = cert.issuerCertificate
            }
            console.log(certPEM)
            fs.writeFileSync('./cacert.pem', certPEM)
            let chunks = []
            res.on('data', chunk => chunks.push(chunk))
            res.on('end', () => {
                console.log('DONE', Buffer.concat(chunks).toString('utf8'))
            })
        })
    }
}).on('error', (err) => {
    console.error('error', err)
}).end()
";
        private string _logFile = null;

        public int Order => 50;

        public string CheckName => "Node.js Certificate/Proxy Validation";

        public string CheckDescription => "Make sure the node.js have access to the GitHub Enterprise Server.";

        public string CheckLog => _logFile;

        public string HelpLink => "https://github.com/actions/runner/docs/checks/nodejs.md";

        public Type ExtensionType => typeof(ICheckExtension);

        public override void Initialize(IHostContext hostContext)
        {
            base.Initialize(hostContext);
            _logFile = Path.Combine(HostContext.GetDirectory(WellKnownDirectory.Diag), StringUtil.Format("{0}_{1:yyyyMMdd-HHmmss}-utc.log", nameof(NodeJsCheck), DateTime.UtcNow));
        }

        // node access to ghes/gh
        public async Task<bool> RunCheck(string url, string pat)
        {
            var result = true;
            var checkTasks = new List<Task<CheckResult>>();

            checkTasks.Add(CheckNodeJs(url, pat));

            while (checkTasks.Count > 0)
            {
                var finishedCheckTask = await Task.WhenAny<CheckResult>(checkTasks);
                var finishedCheck = await finishedCheckTask;
                result = result && finishedCheck.Pass;
                await File.AppendAllLinesAsync(_logFile, finishedCheck.Logs);
                checkTasks.Remove(finishedCheckTask);

                if (finishedCheck.SslError)
                {
                    checkTasks.Add(CheckNodeJsWithExtraCA(url, pat));
                }
            }

            await Task.WhenAll(checkTasks);
            return result;
        }

        private async Task<CheckResult> CheckNodeJsWithExtraCA(string url, string pat)
        {
            var result = new CheckResult();
            var node12 = Path.Combine(HostContext.GetDirectory(WellKnownDirectory.Externals), "node12", "bin", $"node{IOUtil.ExeExtension}");
            try
            {
                // Request to untrusted-root.badssl.com
                var tempJsFile = Path.Combine(HostContext.GetDirectory(WellKnownDirectory.Diag), StringUtil.Format("{0}_{1:yyyyMMdd-HHmmss}-utc.js", nameof(NodeJsCheck), DateTime.UtcNow));
                var repoUrlBuilder = new UriBuilder(url);
                var proxy = HostContext.WebProxy.GetProxy(repoUrlBuilder.Uri);
                if (proxy != null)
                {
                    var script = _nodejsCertWithProxyScript.Replace("<HOSTNAME>", "untrusted-root.badssl.com").Replace("<PORT>", "443").Replace("<PROXYHOST>", proxy.Host).Replace("<PROXYPORT>", proxy.Port.ToString());
                    if (HostContext.WebProxy.Credentials is NetworkCredential proxyCred)
                    {
                        script = script.Replace("<PROXYUSERNAME>", proxyCred.UserName).Replace("<PROXYPASSWORD>", proxyCred.Password);
                    }
                    else
                    {
                        script = script.Replace("<PROXYUSERNAME>", "").Replace("<PROXYPASSWORD>", "");
                    }

                    await File.WriteAllTextAsync(tempJsFile, script);
                }
                else
                {
                    await File.WriteAllTextAsync(tempJsFile, _nodejsCertScript.Replace("<HOSTNAME>", "untrusted-root.badssl.com").Replace("<PORT>", "443"));
                }

                using (var processInvoker = HostContext.CreateService<IProcessInvoker>())
                {
                    processInvoker.OutputDataReceived += new EventHandler<ProcessDataReceivedEventArgs>((sender, args) =>
                    {
                        if (!string.IsNullOrEmpty(args.Data))
                        {
                            result.Logs.Add(args.Data);
                        }
                    });

                    processInvoker.ErrorDataReceived += new EventHandler<ProcessDataReceivedEventArgs>((sender, args) =>
                    {
                        if (!string.IsNullOrEmpty(args.Data))
                        {
                            result.Logs.Add($"[ERROR] {args.Data}");
                        }
                    });

                    await processInvoker.ExecuteAsync(HostContext.GetDirectory(WellKnownDirectory.Root), node12, $"\"{tempJsFile}\"", new Dictionary<string, string> { }, true, CancellationToken.None);
                }

                var recheck = await CheckNodeJs(url, pat);
                result.Logs.AddRange(recheck.Logs);
                result.Pass = recheck.Pass;
                if (result.Pass)
                {
                    result.Logs.Add("Fixed SSL error by providing extra CA certs.");
                }
            }
            catch (Exception ex)
            {
                result.Pass = false;
                result.Logs.Add($"Make https request to github.com using node.js and extra CA failed with error: {ex}");
            }

            return result;
        }

        private async Task<CheckResult> CheckNodeJs(string url, string pat)
        {
            var result = new CheckResult();
            var node12 = Path.Combine(HostContext.GetDirectory(WellKnownDirectory.Externals), "node12", "bin", $"node{IOUtil.ExeExtension}");
            try
            {
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ***************************************************************************************************************");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ****                                                                                                       ****");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ****     Make Http request to {url} using node.js ");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ****                                                                                                       ****");
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} ***************************************************************************************************************");

                // Request to github.com or ghes server
                Uri requestUrl = null;
                var urlBuilder = new UriBuilder(url);
                if (UrlUtil.IsHostedServer(urlBuilder))
                {
                    urlBuilder.Host = $"api.{urlBuilder.Host}";
                }
                else
                {
                    urlBuilder.Path = "api/v3";
                }
                requestUrl = urlBuilder.Uri;

                var tempJsFile = Path.Combine(HostContext.GetDirectory(WellKnownDirectory.Diag), StringUtil.Format("{0}_{1:yyyyMMdd-HHmmss}-utc.js", nameof(NodeJsCheck), DateTime.UtcNow));
                var repoUrlBuilder = new UriBuilder(url);
                var proxy = HostContext.WebProxy.GetProxy(repoUrlBuilder.Uri);
                if (proxy != null)
                {
                    var script = _nodejsWithProxyScript.Replace("<HOSTNAME>", "untrusted-root.badssl.com").Replace("<PORT>", "443").Replace("<PROXYHOST>", proxy.Host).Replace("<PROXYPORT>", proxy.Port.ToString());
                    if (HostContext.WebProxy.Credentials is NetworkCredential proxyCred)
                    {
                        script = script.Replace("<PROXYUSERNAME>", proxyCred.UserName).Replace("<PROXYPASSWORD>", proxyCred.Password);
                    }
                    else
                    {
                        script = script.Replace("<PROXYUSERNAME>", "").Replace("<PROXYPASSWORD>", "");
                    }

                    await File.WriteAllTextAsync(tempJsFile, script);
                }
                else
                {
                    await File.WriteAllTextAsync(tempJsFile, _nodejsScript.Replace("<HOSTNAME>", "untrusted-root.badssl.com").Replace("<PORT>", "443"));
                }

                using (var processInvoker = HostContext.CreateService<IProcessInvoker>())
                {
                    processInvoker.OutputDataReceived += new EventHandler<ProcessDataReceivedEventArgs>((sender, args) =>
                    {
                        if (!string.IsNullOrEmpty(args.Data))
                        {
                            result.Logs.Add($"{DateTime.UtcNow.ToString("O")} [STDOUT] {args.Data}");
                        }
                    });

                    processInvoker.ErrorDataReceived += new EventHandler<ProcessDataReceivedEventArgs>((sender, args) =>
                    {
                        if (!string.IsNullOrEmpty(args.Data))
                        {
                            result.Logs.Add($"{DateTime.UtcNow.ToString("O")} [STDERR] {args.Data}");
                        }
                    });

                    await processInvoker.ExecuteAsync(HostContext.GetDirectory(WellKnownDirectory.Root), node12, $"\"{tempJsFile}\"", new Dictionary<string, string> { { "NODE_EXTRA_CA_CERTS", Path.Combine(HostContext.GetDirectory(WellKnownDirectory.Root), "cacert.pem") } }, true, CancellationToken.None);
                }

                result.Pass = true;
            }
            catch (Exception ex)
            {
                result.Pass = false;
                result.Logs.Add($"{DateTime.UtcNow.ToString("O")} Make https request to github.com using node.js failed with error: {ex}");
                if (result.Logs.Any(x => x.Contains("UNABLE_TO_VERIFY_LEAF_SIGNATURE") ||
                                         x.Contains("UNABLE_TO_GET_ISSUER_CERT_LOCALLY") ||
                                         x.Contains("SELF_SIGNED_CERT_IN_CHAIN")))
                {
                    result.Logs.Add($"{DateTime.UtcNow.ToString("O")} Https request failed due to SSL cert issue.");
                    result.SslError = true;
                }
            }

            return result;
        }
    }
}