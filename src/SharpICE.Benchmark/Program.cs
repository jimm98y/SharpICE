// What the data paths allocate, and how fast they go: of each scenario, the bytes allocated per packet delivered (of all the
// process's threads), the garbage collections, and the packets per second - over loopback, a window of packets in flight.
// Usage: SharpICE.Benchmark [packets] [ice|turn] [--trace]; run it in Release. --trace lists the types allocated, sampled.
using SharpICE;
using SharpStunClient;
using SharpStunServer;
using SharpTurnClient;
using SharpTurnServer;
using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.Net;
using System.Net.Sockets;

const int Size = 1200;      // a media packet
const int Window = 32;      // packets in flight at most

bool trace = args.Contains("--trace");
var positional = args.Where(a => !a.StartsWith("--")).ToArray();
int count = positional.Length > 0 ? int.Parse(positional[0]) : 200_000;
string only = positional.Length > 1 ? positional[1] : null;

Console.WriteLine($"{count} packets of {Size} bytes, .NET {Environment.Version}, server GC {System.Runtime.GCSettings.IsServerGC}");
Console.WriteLine($"{"scenario",-28} {"B/packet",10} {"gen0",6} {"gen1",6} {"gen2",6} {"packets/s",11} {"delivered",10}");

if (only == null || only == "ice")
    await IceUdp();
if (only == null || only == "turn")
{
    foreach (string transport in new[] { "udp", "tcp" })
    {
        await Turn(transport, toClient: true);
        await Turn(transport, toClient: false);
    }
}

// two agents on loopback, connected; data of one to the other
async Task IceUdp()
{
    using var a = Agent(IceRole.Controlling);
    using var b = Agent(IceRole.Controlled);
    await a.GatherCandidatesAsync();
    await b.GatherCandidatesAsync();
    a.SetRemoteCredentials(b.LocalUfrag, b.LocalPassword);
    b.SetRemoteCredentials(a.LocalUfrag, a.LocalPassword);
    foreach (var candidate in b.LocalCandidates)
        a.AddRemoteCandidate(candidate.ToString());
    foreach (var candidate in a.LocalCandidates)
        b.AddRemoteCandidate(candidate.ToString());
    a.Start();
    b.Start();
    while (a.SelectedPair?.Nominated != true || b.SelectedPair?.Nominated != true)
        await Task.Delay(20);

    long received = 0;
    b.DataReceived += (s, e) => Interlocked.Increment(ref received);
    byte[] packet = new byte[Size];
    Run("ICE UDP a -> b", () => Volatile.Read(ref received), () => a.Send(packet, 0, packet.Length));
}

// an allocation of a server on loopback, a channel bound to a peer; data of the peer to the client, or of the client to it
async Task Turn(string transport, bool toClient)
{
    var serverOptions = new TurnServerOptions
    {
        Stun = new StunServerOptions { Realm = "benchmark", Users = new Dictionary<string, string> { ["user"] = "pass" }, AuthenticateBinding = false },
        // its peer is of the loopback
        AllowPeer = peer => true,
    };
    using var server = new TurnServer(serverOptions);
    var listener = transport == "udp" ? server.ListenUdp(new IPEndPoint(IPAddress.Loopback, 0)) : server.ListenTcp(new IPEndPoint(IPAddress.Loopback, 0));
    using var client = new TurnClient(new StunClientOptions { Username = "user", Password = "pass" });
    await client.ConnectAsync($"turn:127.0.0.1:{listener.Port}?transport={transport}");
    await client.AllocateAsync();

    using var peer = new Peer();
    await client.BindChannelAsync(peer.EndPoint);
    var relayed = client.RelayedEndPoint;
    // the permission and the channel used once, the peer learning where the relay is
    await client.SendAsync(peer.EndPoint, new byte[1]);
    while (Volatile.Read(ref peer.Received) == 0)
        await Task.Delay(10);

    byte[] packet = new byte[Size];
    if (toClient)
    {
        long received = 0;
        client.DataReceived += (s, e) => Interlocked.Increment(ref received);
        Run($"TURN {transport.ToUpperInvariant()} peer -> client", () => Volatile.Read(ref received), () => peer.Send(packet, relayed));
    }
    else
    {
        long start = Volatile.Read(ref peer.Received);
        Run($"TURN {transport.ToUpperInvariant()} client -> peer", () => Volatile.Read(ref peer.Received) - start, () => client.SendAsync(peer.EndPoint, packet).GetAwaiter().GetResult());
    }
}

void Run(string name, Func<long> received, Action send)
{
    // warmed up first: the JIT, the pools, the caches
    Pump(count / 10, received, send);
    GC.Collect();
    GC.WaitForPendingFinalizers();
    GC.Collect();

    using var listener = trace ? new AllocationListener() : null;
    long before = received();
    long bytes = GC.GetTotalAllocatedBytes(true);
    int gen0 = GC.CollectionCount(0), gen1 = GC.CollectionCount(1), gen2 = GC.CollectionCount(2);
    var watch = Stopwatch.StartNew();
    Pump(count, received, send);
    watch.Stop();
    long allocated = GC.GetTotalAllocatedBytes(true) - bytes;
    long delivered = received() - before;
    Console.WriteLine($"{name,-28} {allocated / (double)Math.Max(1, delivered),10:F1} {GC.CollectionCount(0) - gen0,6} {GC.CollectionCount(1) - gen1,6} {GC.CollectionCount(2) - gen2,6} {delivered / watch.Elapsed.TotalSeconds,11:F0} {delivered,10}");
    listener?.Print();
}

// sends at most a window ahead of what arrived; of a packet lost, on after 100 ms; then waits for the last to arrive
static void Pump(int packets, Func<long> received, Action send)
{
    long start = received();
    var stall = new Stopwatch();
    for (int sent = 0; sent < packets; sent++)
    {
        stall.Restart();
        while (sent - (received() - start) >= Window && stall.ElapsedMilliseconds < 100)
            Thread.SpinWait(20);
        if (stall.ElapsedMilliseconds >= 100)
            start = received() - sent + Window / 2;
        send();
    }
    var settle = Stopwatch.StartNew();
    long last = -1;
    while (settle.ElapsedMilliseconds < 500 && received() != last)
    {
        last = received();
        Thread.Sleep(20);
    }
}

static IceAgent Agent(IceRole role) => new IceAgent(new IceAgentOptions
{
    Role = role,
    IncludeLoopback = true,
    AddressFilter = address => IPAddress.IsLoopback(address) && address.AddressFamily == AddressFamily.InterNetwork,
});

/// <summary>A peer of the relay: a socket that counts what it receives, of no allocation of its own.</summary>
sealed class Peer : IDisposable
{
    private readonly Socket _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    private readonly Dictionary<IPEndPoint, SocketAddress> _addresses = new Dictionary<IPEndPoint, SocketAddress>();
    public long Received;

    public Peer()
    {
        _socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        _socket.ReceiveBufferSize = 4 << 20;
        EndPoint = (IPEndPoint)_socket.LocalEndPoint;
        new Thread(Receive) { IsBackground = true, Name = "Peer" }.Start();
    }

    public IPEndPoint EndPoint { get; }

    private void Receive()
    {
        byte[] buffer = new byte[65536];
        var from = new SocketAddress(AddressFamily.InterNetwork);
        try
        {
            while (true)
            {
                _socket.ReceiveFrom(buffer, SocketFlags.None, from);
                Interlocked.Increment(ref Received);
            }
        }
        catch (Exception ex) when (ex is SocketException || ex is ObjectDisposedException)
        {
        }
    }

    public void Send(byte[] data, IPEndPoint to)
    {
        if (!_addresses.TryGetValue(to, out var address))
            _addresses[to] = address = to.Serialize();
        _socket.SendTo(data, SocketFlags.None, address);
    }

    public void Dispose() => _socket.Dispose();
}

/// <summary>The types allocated, as the runtime samples them: one GCAllocationTick of each 100 KB or so.</summary>
sealed class AllocationListener : EventListener
{
    private readonly Dictionary<string, int> _types = new Dictionary<string, int>();

    protected override void OnEventSourceCreated(EventSource source)
    {
        // the GC keyword
        if (source.Name == "Microsoft-Windows-DotNETRuntime")
            EnableEvents(source, EventLevel.Verbose, (EventKeywords)0x1);
    }

    protected override void OnEventWritten(EventWrittenEventArgs e)
    {
        if (e.EventName == null || !e.EventName.StartsWith("GCAllocationTick") || e.PayloadNames == null)
            return;
        int index = e.PayloadNames.IndexOf("TypeName");
        string type = index >= 0 ? e.Payload[index] as string ?? "?" : "?";
        lock (_types)
            _types[type] = _types.TryGetValue(type, out int n) ? n + 1 : 1;
    }

    public void Print()
    {
        lock (_types)
        {
            foreach (var pair in _types.OrderByDescending(p => p.Value).Take(8))
                Console.WriteLine($"    {pair.Value,5}  {pair.Key}");
        }
    }
}
