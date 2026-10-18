// A TURN client: a relayed address allocated, and the data of peers sent to it printed.
// Usage: TurnClientSample uri username password [peer], e.g. turn:127.0.0.1:3478?transport=udp user pass 192.0.2.1:5000
using SharpStunClient;
using SharpTurnClient;
using System.Net;
using System.Text;

if (args.Length < 3)
{
    Console.WriteLine("Usage: TurnClientSample uri username password [peer]");
    return;
}

using var turn = new TurnClient(new StunClientOptions { Username = args[1], Password = args[2] });
await turn.ConnectAsync(args[0]);
turn.DataReceived += (s, e) => Console.WriteLine($"{e.Peer}: {Encoding.UTF8.GetString(e.Buffer, e.Offset, e.Count)}");
await turn.AllocateAsync();
Console.WriteLine($"Relayed: {turn.RelayedEndPoint}");
Console.WriteLine($"Mapped:  {turn.MappedEndPoint}");

// a peer's permission installed of the data sent to it: only then is what it sends relayed back
if (args.Length > 3)
{
    var peer = IPEndPoint.Parse(args[3]);
    await turn.SendAsync(peer, Encoding.UTF8.GetBytes("Hello from TURN"));
    Console.WriteLine($"Sent to {peer}");
}

Console.WriteLine("Press Enter to stop.");
Console.ReadLine();
await turn.DeallocateAsync();
