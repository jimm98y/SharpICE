// A TURN server of UDP relays over UDP and TCP, and of TCP allocations over TCP, of one user's long-term credentials:
// TurnClientSample's of its defaults. Of its relays of the loopback by default, and of peers of the loopback - of a demo
// on one host alone; of a relay address given, of public peers alone, as of a server of the internet.
// Usage: TurnServerSample [port] [username] [password] [realm] [relayAddress]
using SharpStun;
using SharpTurn;
using System.Net;

int port = args.Length > 0 ? int.Parse(args[0]) : 3479;
string username = args.Length > 1 ? args[1] : "user";
string password = args.Length > 2 ? args[2] : "pass";
string realm = args.Length > 3 ? args[3] : "example.org";
var relayAddress = args.Length > 4 ? IPAddress.Parse(args[4]) : IPAddress.Loopback;

using var server = new TurnServer(new TurnServerOptions
{
    Stun = new StunServerOptions
    {
        Realm = realm,
        Users = new Dictionary<string, string> { [username] = password },
        AuthenticateBinding = false,
        Trace = Console.WriteLine,
    },
    RelayAddress = relayAddress,
    // of a demo on this host, its peers of the loopback too; never of the private networks, as a sample is no relay into them
    AllowPeer = IPAddress.IsLoopback(relayAddress) ? peer => IPAddress.IsLoopback(peer.Address) || TurnPeers.IsPublic(peer) : TurnPeers.IsPublic,
    Trace = Console.WriteLine,
});
server.ListenUdp(new IPEndPoint(IPAddress.Any, port));
server.ListenTcp(new IPEndPoint(IPAddress.Any, port));

Console.WriteLine($"TURN server on port {port}, relays of {relayAddress}, user {username}, password {password}, realm {realm}.");
Console.WriteLine($"Run TurnClientSample, of turn:127.0.0.1:{port} or turn:127.0.0.1:{port}?transport=tcp. Press Enter to stop.");
Console.ReadLine();
