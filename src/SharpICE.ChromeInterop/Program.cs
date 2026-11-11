// ICE of SharpICE of Chrome's (libwebrtc): a headless Chrome driven of its DevTools protocol, an RTCPeerConnection of a
// data channel, and an IceAgent the other side of it - each of the offer in turn, of UDP and of TCP, of Chrome's mDNS
// names and of SharpICE's own. The SDP's fingerprint is no DTLS of SharpICE's, which does no DTLS: what is checked is
// ICE alone - Chrome's iceConnectionState, the agent's nominated pair, and both of consent freshness for a while.
// Usage: SharpICE.ChromeInterop [path to chrome.exe] [scenario...]; exit code 0 of every scenario passed.
using SharpICE;
using System.Diagnostics;
using System.Net;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

string chromePath = args.FirstOrDefault(a => a.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || File.Exists(a))
    ?? new[]
    {
        @"C:\Program Files\Google\Chrome\Application\chrome.exe",
        @"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/usr/bin/google-chrome",
    }.FirstOrDefault(File.Exists);
if (chromePath == null)
{
    Console.WriteLine("No Chrome found: give its path.");
    return 2;
}
var only = args.Where(a => !File.Exists(a)).ToHashSet(StringComparer.OrdinalIgnoreCase);

var scenarios = new (string Name, bool ChromeOffers, bool Tcp, bool ChromeMdns, bool AgentMdns)[]
{
    ("chrome-offers-udp", true, false, true, false),
    ("agent-offers-udp", false, false, true, false),
    ("chrome-offers-udp-no-mdns", true, false, false, false),
    ("agent-offers-udp-agent-mdns", false, false, false, true),
    ("chrome-offers-tcp", true, true, false, false),
    ("agent-offers-tcp", false, true, false, false),
};

int failed = 0;
foreach (var scenario in scenarios.Where(s => only.Count == 0 || only.Contains(s.Name)))
{
    Console.WriteLine($"=== {scenario.Name}");
    try
    {
        await using var chrome = await Chrome.LaunchAsync(chromePath, scenario.ChromeMdns);
        string result = await RunAsync(chrome, scenario.ChromeOffers, scenario.Tcp, scenario.AgentMdns);
        Console.WriteLine($"PASS {scenario.Name}: {result}");
    }
    catch (Exception ex)
    {
        failed++;
        Console.WriteLine($"FAIL {scenario.Name}: {ex.Message}");
    }
}
Console.WriteLine(failed == 0 ? "All passed." : $"{failed} failed.");
return failed == 0 ? 0 : 1;

static async Task<string> RunAsync(Chrome chrome, bool chromeOffers, bool tcp, bool agentMdns)
{
    var trace = new List<string>();
    using var agent = new IceAgent(new IceAgentOptions
    {
        Role = chromeOffers ? IceRole.Controlled : IceRole.Controlling,
        IncludeUdp = !tcp,
        IncludeTcp = tcp,
        IncludeIPv6 = false,
        MdnsCandidates = agentMdns,
        Trace = line => { lock (trace) trace.Add(DateTime.Now.ToString("HH:mm:ss.fff ") + line); },
    });
    await agent.GatherCandidatesAsync();
    // of TCP alone, Chrome's and the agent's candidates of TCP alone
    Func<IceCandidate, bool> ours = c => tcp ? c.IsTcp : c.IsUdp;

    string remoteSdp;
    await chrome.EvaluateAsync("window.pc = new RTCPeerConnection(); window.dc = pc.createDataChannel('ice'); true");
    if (chromeOffers)
    {
        remoteSdp = await chrome.EvaluateAsync(@"(async () => {
            await pc.setLocalDescription(await pc.createOffer());
            await new Promise(r => { if (pc.iceGatheringState === 'complete') r(); pc.addEventListener('icegatheringstatechange', () => { if (pc.iceGatheringState === 'complete') r(); }); });
            return pc.localDescription.sdp; })()");
        var offer = Sdp.Parse(remoteSdp);
        agent.SetRemoteCredentials(offer.Ufrag, offer.Pwd);
        int added = offer.Candidates.Count(c => (tcp ? c.Contains(" tcp ") : c.Contains(" udp ")) && agent.AddRemoteCandidate(c));
        agent.SetRemoteGatheringComplete();
        string answer = Sdp.Build(agent, offer.Mid, "active", ours);
        await chrome.EvaluateAsync($"pc.setRemoteDescription({{ type: 'answer', sdp: {JsonSerializer.Serialize(answer)} }}).then(() => true)");
        agent.Start();
        trace.Add($"{added} of Chrome's candidates taken");
    }
    else
    {
        string offerSdp = Sdp.Build(agent, "0", "actpass", ours);
        remoteSdp = await chrome.EvaluateAsync($@"(async () => {{
            await pc.setRemoteDescription({{ type: 'offer', sdp: {JsonSerializer.Serialize(offerSdp)} }});
            await pc.setLocalDescription(await pc.createAnswer());
            await new Promise(r => {{ if (pc.iceGatheringState === 'complete') r(); pc.addEventListener('icegatheringstatechange', () => {{ if (pc.iceGatheringState === 'complete') r(); }}); }});
            return pc.localDescription.sdp; }})()");
        var answer = Sdp.Parse(remoteSdp);
        agent.SetRemoteCredentials(answer.Ufrag, answer.Pwd);
        int added = answer.Candidates.Count(c => (tcp ? c.Contains(" tcp ") : c.Contains(" udp ")) && agent.AddRemoteCandidate(c));
        agent.SetRemoteGatheringComplete();
        agent.Start();
        trace.Add($"{added} of Chrome's candidates taken");
    }

    // ICE of both: Chrome's connected, the agent's pair nominated
    var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(20);
    string state = "";
    while (DateTime.UtcNow < deadline)
    {
        state = await chrome.EvaluateAsync("pc.iceConnectionState");
        if ((state == "connected" || state == "completed") && agent.SelectedPair?.Nominated == true)
            break;
        if (state == "failed")
            break;
        await Task.Delay(100);
    }
    if (!((state == "connected" || state == "completed") && agent.SelectedPair?.Nominated == true))
        throw new Exception($"Chrome {state}, agent {agent.State} {agent.SelectedPair}{Environment.NewLine}{Tail(trace)}");
    string pair = agent.SelectedPair.ToString();

    // consent freshness of both ways (RFC 7675): still connected past two of Chrome's and the agent's consent checks
    await Task.Delay(TimeSpan.FromSeconds(12));
    state = await chrome.EvaluateAsync("pc.iceConnectionState");
    if (!(state == "connected" || state == "completed") || agent.State == IceConnectionState.Disconnected || agent.State == IceConnectionState.Failed)
        throw new Exception($"no consent after 12 s: Chrome {state}, agent {agent.State}{Environment.NewLine}{Tail(trace)}");
    string chromePair = await chrome.EvaluateAsync(@"(async () => {
        const stats = await pc.getStats(); let pair = null;
        stats.forEach(s => { if (s.type === 'transport' && s.selectedCandidatePairId) pair = stats.get(s.selectedCandidatePairId); });
        if (!pair) return 'none';
        const local = stats.get(pair.localCandidateId), remote = stats.get(pair.remoteCandidateId);
        return `${local.candidateType} ${local.protocol} ${local.address}:${local.port} -> ${remote.candidateType} ${remote.protocol} ${remote.address}:${remote.port}, requests ${pair.requestsSent}/${pair.responsesReceived}, consent ${pair.consentRequestsSent ?? '-'}`; })()");
    return $"agent {pair}; Chrome {chromePair}";
}

static string Tail(List<string> trace)
{
    lock (trace)
        return string.Join(Environment.NewLine, trace.Skip(Math.Max(0, trace.Count - 25)));
}

/// <summary>What of an SDP of Chrome's ICE takes: its credentials, its candidates, its first m-line's mid.</summary>
sealed class Sdp
{
    public string Ufrag;
    public string Pwd;
    public string Mid = "0";
    public List<string> Candidates = new();

    public static Sdp Parse(string sdp)
    {
        var parsed = new Sdp();
        foreach (var raw in sdp.Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            if (line.StartsWith("a=ice-ufrag:")) parsed.Ufrag ??= line.Substring(12);
            else if (line.StartsWith("a=ice-pwd:")) parsed.Pwd ??= line.Substring(10);
            else if (line.StartsWith("a=mid:")) parsed.Mid = line.Substring(6);
            else if (line.StartsWith("a=candidate:")) parsed.Candidates.Add(line.Substring(2));
        }
        return parsed;
    }

    /// <summary>
    /// A data channel's m-line of the agent's credentials and candidates: of a fingerprint of no certificate, as ICE alone is
    /// of the test.
    /// </summary>
    public static string Build(IceAgent agent, string mid, string setup, Func<IceCandidate, bool> which)
    {
        var sdp = new StringBuilder();
        sdp.Append("v=0\r\no=- 4611731400430051336 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n");
        sdp.Append($"a=group:BUNDLE {mid}\r\na=extmap-allow-mixed\r\na=msid-semantic: WMS\r\n");
        sdp.Append("m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\n");
        sdp.Append($"a=ice-ufrag:{agent.LocalUfrag}\r\na=ice-pwd:{agent.LocalPassword}\r\na=ice-options:trickle\r\n");
        sdp.Append("a=fingerprint:sha-256 " + string.Join(":", Enumerable.Range(0, 32).Select(i => (i * 7 % 256).ToString("X2"))) + "\r\n");
        sdp.Append($"a=setup:{setup}\r\na=mid:{mid}\r\na=sctp-port:5000\r\na=max-message-size:262144\r\n");
        foreach (var candidate in agent.LocalCandidates.Where(which))
            sdp.Append("a=").Append(candidate).Append("\r\n");
        sdp.Append("a=end-of-candidates\r\n");
        return sdp.ToString();
    }
}

/// <summary>A headless Chrome of its own profile, of the DevTools protocol over a WebSocket of its page.</summary>
sealed class Chrome : IAsyncDisposable
{
    private readonly Process _process;
    private readonly string _profile;
    private readonly ClientWebSocket _socket = new();
    private int _id;

    private Chrome(Process process, string profile)
    {
        _process = process;
        _profile = profile;
    }

    public static async Task<Chrome> LaunchAsync(string path, bool mdns)
    {
        string profile = Path.Combine(Path.GetTempPath(), "sharpice-chrome-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(profile);
        var start = new ProcessStartInfo(path)
        {
            UseShellExecute = false,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        };
        foreach (string arg in new[]
        {
            "--headless=new", "--remote-debugging-port=0", $"--user-data-dir={profile}", "--no-first-run", "--no-default-browser-check",
            "--disable-gpu", "--disable-extensions", mdns ? "--enable-features=WebRtcHideLocalIpsWithMdns" : "--disable-features=WebRtcHideLocalIpsWithMdns",
            "about:blank",
        })
            start.ArgumentList.Add(arg);
        var process = Process.Start(start);
        var chrome = new Chrome(process, profile);
        string portFile = Path.Combine(profile, "DevToolsActivePort");
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(20);
        while (!File.Exists(portFile) && DateTime.UtcNow < deadline)
            await Task.Delay(100);
        string[] lines = await File.ReadAllLinesAsync(portFile);
        using var http = new HttpClient();
        var targets = JsonNode.Parse(await http.GetStringAsync($"http://127.0.0.1:{lines[0]}/json/list")).AsArray();
        string url = targets.First(t => (string)t["type"] == "page")["webSocketDebuggerUrl"].ToString();
        await chrome._socket.ConnectAsync(new Uri(url), CancellationToken.None);
        return chrome;
    }

    /// <summary>A JavaScript expression's value, of a promise awaited; of an exception thrown, its text.</summary>
    public async Task<string> EvaluateAsync(string expression)
    {
        int id = Interlocked.Increment(ref _id);
        var request = new JsonObject
        {
            ["id"] = id,
            ["method"] = "Runtime.evaluate",
            ["params"] = new JsonObject { ["expression"] = expression, ["awaitPromise"] = true, ["returnByValue"] = true },
        };
        await _socket.SendAsync(Encoding.UTF8.GetBytes(request.ToJsonString()), WebSocketMessageType.Text, true, CancellationToken.None);
        var buffer = new byte[1 << 20];
        while (true)
        {
            using var message = new MemoryStream();
            WebSocketReceiveResult result;
            do
            {
                result = await _socket.ReceiveAsync(buffer, CancellationToken.None);
                message.Write(buffer, 0, result.Count);
            }
            while (!result.EndOfMessage);
            var response = JsonNode.Parse(message.ToArray());
            if ((int?)response["id"] != id)
                continue;
            var value = response["result"]?["result"]?["value"];
            var exception = response["result"]?["exceptionDetails"];
            if (exception != null)
                throw new Exception("Chrome: " + (exception["exception"]?["description"] ?? exception["text"]));
            return value?.ToString() ?? "";
        }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            if (_socket.State == WebSocketState.Open)
                await _socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "", CancellationToken.None);
        }
        catch (WebSocketException)
        {
        }
        try
        {
            _process.Kill(true);
            await _process.WaitForExitAsync();
        }
        catch (InvalidOperationException)
        {
        }
        for (int attempt = 0; attempt < 10; attempt++)
        {
            try
            {
                Directory.Delete(_profile, true);
                break;
            }
            catch (IOException)
            {
                await Task.Delay(200);
            }
            catch (UnauthorizedAccessException)
            {
                await Task.Delay(200);
            }
        }
    }
}
