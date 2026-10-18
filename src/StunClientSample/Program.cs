// A STUN client: the address a server sees this host's requests of.
// Usage: StunClientSample [uri] [username] [password], e.g. stun:stun.l.google.com:19302 or stuns:stun.example.org
using SharpStunClient;

string uri = args.Length > 0 ? args[0] : "stun:stun.l.google.com:19302";
var options = new StunClientOptions { Username = args.Length > 1 ? args[1] : null, Password = args.Length > 2 ? args[2] : null };

using var client = new StunClient(options);
await client.ConnectAsync(uri);
Console.WriteLine($"Server:  {client.Transport.RemoteEndPoint}");
Console.WriteLine($"Local:   {client.Transport.LocalEndPoint}");
Console.WriteLine($"Mapped:  {await client.GetMappedAddressAsync()}");
