// A TURN server of UDP relays over UDP and TCP, of one user's long-term credentials.
// Usage: TurnServerSample [port] [username] [password] [realm]
using SharpStunServer;
using SharpTurnServer;
using System.Net;

int port = args.Length > 0 ? int.Parse(args[0]) : 3478;
string username = args.Length > 1 ? args[1] : "user";
string password = args.Length > 2 ? args[2] : "pass";
string realm = args.Length > 3 ? args[3] : "example.org";

using var server = new TurnServer(new TurnServerOptions
{
    Stun = new StunServerOptions
    {
        Realm = realm,
        Users = new Dictionary<string, string> { [username] = password },
        AuthenticateBinding = false,
        Trace = Console.WriteLine,
    },
    Trace = Console.WriteLine,
});
server.ListenUdp(new IPEndPoint(IPAddress.Any, port));
server.ListenTcp(new IPEndPoint(IPAddress.Any, port));

Console.WriteLine($"TURN server on port {port}, user {username}, realm {realm}. Press Enter to stop.");
Console.ReadLine();
