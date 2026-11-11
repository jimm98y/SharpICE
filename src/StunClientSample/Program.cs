// A STUN client: the address a server sees this host's requests of. Of its defaults, of StunServerSample on this host.
// Usage: StunClientSample [uri] [username] [password], e.g. stun:127.0.0.1:3478, stun:stun.l.google.com:19302 or
// stuns:stun.example.org; or StunClientSample --tcp [host:port], of STUN over TCP, as a STUN URI has no transport (RFC 7064)
using SharpStun;
using System.Net;
using System.Net.Sockets;

bool tcp = args.Length > 0 && args[0] == "--tcp";
string target = tcp ? (args.Length > 1 ? args[1] : "127.0.0.1:3478") : (args.Length > 0 ? args[0] : "stun:127.0.0.1:3478");
var options = new StunClientOptions
{
    Username = !tcp && args.Length > 1 ? args[1] : null,
    Password = !tcp && args.Length > 2 ? args[2] : null,
};

try
{
    using var client = tcp ? new StunClient(await StunStreamTransport.ConnectAsync(IPEndPoint.Parse(target)), options) : new StunClient(options);
    if (!tcp)
        await client.ConnectAsync(target);
    var mapped = await client.GetMappedAddressAsync();
    Console.WriteLine($"Server:  {client.Transport.RemoteEndPoint} ({(tcp ? "TCP" : "of the URI's transport")})");
    Console.WriteLine($"Local:   {client.Transport.LocalEndPoint}");
    Console.WriteLine(mapped != null ? $"Mapped:  {mapped}" : "No answer: is StunServerSample running?");
    if (tcp)
        client.Transport.Dispose();
}
catch (Exception ex) when (ex is StunException || ex is SocketException || ex is IOException || ex is FormatException)
{
    Console.WriteLine($"{target}: {ex.Message} - is StunServerSample running?");
}
