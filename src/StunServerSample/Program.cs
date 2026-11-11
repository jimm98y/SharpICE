// A STUN server of the Binding method over UDP and TCP, IPv4 and IPv6: StunClientSample's of its defaults.
// Usage: StunServerSample [port]
using SharpSTUN;
using System.Net;

int port = args.Length > 0 ? int.Parse(args[0]) : 3478;

using var server = new StunServer(new StunServerOptions { Trace = Console.WriteLine });
server.ListenUdp(new IPEndPoint(IPAddress.Any, port));
server.ListenTcp(new IPEndPoint(IPAddress.Any, port));
server.ListenUdp(new IPEndPoint(IPAddress.IPv6Any, port));
server.ListenTcp(new IPEndPoint(IPAddress.IPv6Any, port));

Console.WriteLine($"STUN server on port {port}: run StunClientSample, of stun:127.0.0.1:{port}, or of --tcp 127.0.0.1:{port}. Press Enter to stop.");
Console.ReadLine();
