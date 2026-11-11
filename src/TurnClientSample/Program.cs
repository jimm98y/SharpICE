// A TURN client: a relayed address allocated, data relayed to a peer and back. Of its defaults, of TurnServerSample on this
// host, of a peer of its own - a UDP socket of the loopback, which echoes what it gets - the data's round trip through the
// relay shown.
// Usage: TurnClientSample [uri] [username] [password] [peer], e.g. turn:127.0.0.1:3479 user pass, or of a peer of another
// host's, 192.0.2.1:5000
using SharpStun;
using SharpTurn;
using System.Net;
using System.Net.Sockets;
using System.Text;

string uri = args.Length > 0 ? args[0] : "turn:127.0.0.1:3479";
string username = args.Length > 1 ? args[1] : "user";
string password = args.Length > 2 ? args[2] : "pass";

using var turn = new TurnClient(new StunClientOptions { Username = username, Password = password });
try
{
    await turn.ConnectAsync(uri);
    await turn.AllocateAsync();
}
catch (Exception ex) when (ex is StunException || ex is TurnException || ex is SocketException || ex is IOException)
{
    Console.WriteLine($"{uri}: {ex.Message} - is TurnServerSample running?");
    return;
}
var echoed = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
turn.DataReceived += (s, e) =>
{
    string text = Encoding.UTF8.GetString(e.Buffer, e.Offset, e.Count);
    Console.WriteLine($"{e.Peer}: {text}");
    echoed.TrySetResult(text);
};
Console.WriteLine($"Relayed: {turn.RelayedEndPoint}");
Console.WriteLine($"Mapped:  {turn.MappedEndPoint}");

if (args.Length > 3)
{
    // a peer of another host's: a permission of its address installed of the data sent to it - only then is what it sends
    // relayed back
    var peer = IPEndPoint.Parse(args[3]);
    await turn.SendAsync(peer, Encoding.UTF8.GetBytes("Hello from TURN"));
    Console.WriteLine($"Sent to {peer}. Press Enter to stop.");
    Console.ReadLine();
}
else
{
    // a peer of the loopback, of this sample's own, which echoes what the relay sends it back to the relay
    using var peer = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    peer.Bind(new IPEndPoint(IPAddress.Loopback, 0));
    var echo = Task.Run(() =>
    {
        byte[] buffer = new byte[1500];
        EndPoint from = new IPEndPoint(IPAddress.Any, 0);
        int count = peer.ReceiveFrom(buffer, ref from);
        Console.WriteLine($"Peer {peer.LocalEndPoint} got \"{Encoding.UTF8.GetString(buffer, 0, count)}\" of {from}, the relayed address; echoing it");
        peer.SendTo(buffer, 0, count, SocketFlags.None, from);
    });
    await turn.SendAsync((IPEndPoint)peer.LocalEndPoint, Encoding.UTF8.GetBytes("Hello from TURN"));
    var done = await Task.WhenAny(echoed.Task, Task.Delay(TimeSpan.FromSeconds(5)));
    Console.WriteLine(done == echoed.Task ? "Relayed to the peer and back." : "No echo of the peer: does TurnServerSample relay of the loopback?");
}

await turn.DeallocateAsync();
