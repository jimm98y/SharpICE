# SharpICE
STUN, TURN and ICE client and server written in C#, with no native dependencies.

[![NuGet version](https://img.shields.io/nuget/v/SharpICE.svg?style=flat-square&label=SharpICE)](https://www.nuget.org/packages/SharpICE)
[![NuGet version](https://img.shields.io/nuget/v/SharpSTUN.svg?style=flat-square&label=SharpSTUN)](https://www.nuget.org/packages/SharpSTUN)
[![NuGet version](https://img.shields.io/nuget/v/SharpTURN.svg?style=flat-square&label=SharpTURN)](https://www.nuget.org/packages/SharpTURN)

There are three libraries:
1. SharpSTUN - STUN client and server
1. SharpTURN - TURN client and server, built on SharpSTUN
1. SharpICE - ICE agent, built on SharpSTUN and SharpTURN

Implements the following RFCs:
1. DNS SRV records [RFC2782](https://www.rfc-editor.org/rfc/rfc2782)
1. Framing RTP and RTCP Packets over Connection-Oriented Transport [RFC4571](https://www.rfc-editor.org/rfc/rfc4571)
1. Test Vectors for Session Traversal Utilities for NAT (STUN) [RFC5769](https://www.rfc-editor.org/rfc/rfc5769)
1. Traversal Using Relays around NAT (TURN) Extensions for TCP Allocations [RFC6062](https://www.rfc-editor.org/rfc/rfc6062)
1. TCP Candidates with Interactive Connectivity Establishment (ICE) [RFC6544](https://www.rfc-editor.org/rfc/rfc6544)
1. Multicast DNS [RFC6762](https://www.rfc-editor.org/rfc/rfc6762)
1. URI Scheme for the Session Traversal Utilities for NAT (STUN) Protocol [RFC7064](https://www.rfc-editor.org/rfc/rfc7064)
1. Traversal Using Relays around NAT (TURN) Uniform Resource Identifiers [RFC7065](https://www.rfc-editor.org/rfc/rfc7065)
1. Session Traversal Utilities for NAT (STUN) Usage for Consent Freshness [RFC7675](https://www.rfc-editor.org/rfc/rfc7675)
1. Multiplexing Scheme Updates for Secure Real-time Transport Protocol (SRTP) Extension for Datagram Transport Layer Security (DTLS) [RFC7983](https://www.rfc-editor.org/rfc/rfc7983)
1. Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal [RFC8445](https://www.rfc-editor.org/rfc/rfc8445)
1. Session Traversal Utilities for NAT (STUN) [RFC8489](https://www.rfc-editor.org/rfc/rfc8489)
1. Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN) [RFC8656](https://www.rfc-editor.org/rfc/rfc8656)
1. Trickle ICE: Incremental Provisioning of Candidates for the Interactive Connectivity Establishment (ICE) Protocol [RFC8838](https://www.rfc-editor.org/rfc/rfc8838)
1. Session Description Protocol (SDP) Offer/Answer Procedures for Interactive Connectivity Establishment (ICE) [RFC8839](https://www.rfc-editor.org/rfc/rfc8839)

## DTLS and TLS
STUN and TURN can run over UDP, TCP, TLS and DTLS. DTLS and TLS are based upon [SharpDTLS](https://github.com/jimm98y/SharpDTLS) by default, which supports DTLS 1.2, DTLS 1.3, TLS 1.2 and TLS 1.3. To use another implementation, set `DtlsStack` or `TlsStack` in the client or server options:
1. `DtlsStacks.SharpDtls` (default) - DTLS 1.3 and DTLS 1.2
1. `DtlsStacks.BouncyCastle` - DTLS 1.2 only
1. `TlsStacks.SharpDtls` (default) - TLS 1.3 and TLS 1.2
1. `TlsStacks.BouncyCastle` - TLS 1.2 only
1. `TlsStacks.System` - .NET's `SslStream`

With SharpDTLS and BouncyCastle, the server certificate must have an exportable private key.

## STUN
### Client
Create the STUN client. Username and password are only needed for a server with long-term credentials:
```cs
using var client = new StunClient(new StunClientOptions { Username = "user", Password = "pass" });
```
Connect to the server using a STUN URI. A host without a port is looked up using DNS SRV records and each server is tried in turn:
```cs
await client.ConnectAsync("stun:stun.example.org");
```
Get the address the server sees you at:
```cs
IPEndPoint mapped = await client.GetMappedAddressAsync();
```
Send any other request. When the server asks for credentials, the client sends the request again with them:
```cs
StunMessage response = await client.RequestAsync(new StunMessage(StunMethod.Binding, StunMessageClass.Request));
```
To use TLS, use the "stuns" URI. The server's certificate is checked against the host name:
```cs
await client.ConnectAsync("stuns:stun.example.org");
```
To use DTLS instead of TLS, set `UseDtls`:
```cs
using var client = new StunClient(new StunClientOptions { UseDtls = true });
await client.ConnectAsync("stuns:stun.example.org");
```
For a single Binding request, you don't need a client at all:
```cs
IPEndPoint server = await StunClient.ResolveAsync("stun.l.google.com:19302");
IPEndPoint address = await StunClient.GetMappedAddressAsync(server, TimeSpan.FromSeconds(3));
```
### Server
Create the STUN server. Set `Realm` and `Users` to require long-term credentials. `Certificate` is only needed for TLS and DTLS:
```cs
var server = new StunServer(new StunServerOptions
{
    Realm = "example.org",
    Users = new Dictionary<string, string> { ["user"] = "pass" },
    Certificate = certificate,
});
```
Start the listeners:
```cs
server.ListenUdp(new IPEndPoint(IPAddress.Any, 3478));
server.ListenTcp(new IPEndPoint(IPAddress.Any, 3478));
server.ListenTls(new IPEndPoint(IPAddress.Any, 5349));
server.ListenDtls(new IPEndPoint(IPAddress.Any, 5349));
```
The server answers Binding requests. It supports MD5 and SHA-256 credentials, USERHASH, stateless nonces and ALTERNATE-SERVER redirects. DTLS clients must pass a cookie exchange first, so a spoofed address can't create a connection. Classic STUN (RFC 3489) is not answered.

## TURN
### Client
Create the TURN client and connect to the server. The transport can be UDP, TCP, TLS or DTLS:
```cs
using var turn = new TurnClient(new StunClientOptions { Username = "user", Password = "pass" });
await turn.ConnectAsync("turn:turn.example.org?transport=udp");
```
Allocate the relayed address. The allocation, permissions and channels are refreshed automatically:
```cs
await turn.AllocateAsync();
IPEndPoint relayed = turn.RelayedEndPoint;
```
Receive data from the peers:
```cs
turn.DataReceived += (sender, e) =>
{
    IPEndPoint peer = e.Peer;
    // the data is in e.Buffer, e.Offset, e.Count
};
```
Send data to a peer. A permission for the peer is created first, then the data is sent in a Send indication:
```cs
await turn.SendAsync(peer, data);
```
Bind a channel to send the data to the peer as ChannelData, which has less overhead:
```cs
await turn.BindChannelAsync(peer);
```
Delete the allocation:
```cs
await turn.DeallocateAsync();
```
### TCP Allocations
A TCP allocation relays TCP connections to the peers. Connect to the server over TCP or TLS and allocate:
```cs
using var turn = new TurnClient(new StunClientOptions { Username = "user", Password = "pass" });
await turn.ConnectAsync("turn:turn.example.org?transport=tcp");
await turn.AllocateAsync(new TurnAllocateOptions { Tcp = true });
```
Connect to a peer. The connection is a plain `Stream` of the peer's bytes:
```cs
using var connection = await turn.ConnectPeerAsync(peer);
await connection.Stream.WriteAsync(data, 0, data.Length);
```
Accept the peers that connect to the relayed address. Only peers with a permission can connect:
```cs
await turn.CreatePermissionAsync(peer.Address);
turn.ConnectionAttempt += async (sender, e) =>
{
    using var incoming = await turn.AcceptPeerAsync(e);
    // incoming.Stream
};
```
### Server
Create the TURN server. `RelayAddress` is the public address of the relays:
```cs
var server = new TurnServer(new TurnServerOptions
{
    Stun = new StunServerOptions
    {
        Realm = "example.org",
        Users = new Dictionary<string, string> { ["user"] = "pass" },
        AuthenticateBinding = false,
    },
    RelayAddress = IPAddress.Parse("203.0.113.7"),
});
```
Start the listeners:
```cs
server.ListenUdp(new IPEndPoint(IPAddress.Any, 3478));
server.ListenTcp(new IPEndPoint(IPAddress.Any, 3478));
```
The server supports UDP and TCP allocations, dual-stack allocations, EVEN-PORT, permissions and channels. Its defaults are safe: credentials are required, the relays only reach public unicast addresses (use `AllowPeer` to allow others), the server's own host is never reachable through a relay, and allocations and connections are limited per user and per address.

## ICE
The ICE agent has one component, as WebRTC uses it: RTP and RTCP are multiplexed and all media is bundled.
### Agent
Create the agent with the STUN and TURN servers to gather the candidates from. The offerer is usually controlling, the answerer controlled:
```cs
var options = new IceAgentOptions { Role = IceRole.Controlled };
options.StunServers.Add("stun:stun.l.google.com:19302");
options.TurnServers.Add(new IceTurnServer { Uri = "turn:turn.example.org", Username = "user", Password = "pass" });
var agent = new IceAgent(options);
```
Gather the local candidates and send them to the peer, together with `LocalUfrag` and `LocalPassword`, in the session description or trickled one by one:
```cs
var candidates = await agent.GatherCandidatesAsync();
```
Set the peer's credentials and candidates, then start the checks. Signal the end of the peer's candidates once it has no more:
```cs
agent.SetRemoteCredentials(remoteUfrag, remotePassword);
agent.AddRemoteCandidate("candidate:1 1 udp 2130706431 192.168.1.10 50000 typ host");
agent.Start();
agent.AddRemoteCandidate("a=end-of-candidates");
```
Receive the data that is not STUN, such as DTLS, RTP and RTCP:
```cs
agent.DataReceived += (sender, e) =>
{
    // the data is in e.Buffer, e.Offset, e.Count
};
```
Once `agent.State` is `Connected`, send data to the peer:
```cs
agent.Send(datagram, 0, datagram.Length);
```
To restart ICE, call `Restart` and send a new offer with the new `LocalUfrag`, `LocalPassword` and candidates. When the peer restarts, pass its new credentials; `SetRemoteCredentials` returns true:
```cs
agent.Restart();
bool restarted = agent.SetRemoteCredentials(newRemoteUfrag, newRemotePassword);
```
### Options
1. `IncludeTcp` - gathers ICE-TCP candidates (passive and active), including relayed ones from TURN servers over TCP or TLS. UDP is preferred.
1. `RelayOnly` - uses relayed candidates only.
1. `Lite` - makes the agent an ICE lite agent: host candidates only and no checks of its own.
1. `PublicAddresses` - the public addresses of a 1:1 NAT, such as on a cloud host.
1. `MdnsCandidates` - hides the local addresses behind random ".local" names, as browsers do. The peer's ".local" candidates are always resolved using multicast DNS.

The agent also supports peer reflexive candidates, triggered checks, regular nomination, role conflict resolution and consent freshness.

## Samples
The samples run against each other on one machine with their default settings:
1. `StunServerSample [port]` - STUN server on UDP and TCP, port 3478 by default
1. `StunClientSample [uri] [username] [password]` - shows the address the STUN server sees you at, `stun:127.0.0.1:3478` by default
1. `TurnServerSample [port] [username] [password] [realm] [relayAddress]` - TURN server with UDP and TCP relays, port 3479 by default, user `user` and password `pass`
1. `TurnClientSample [uri] [username] [password] [peer]` - allocates a relay and sends data through it to an echo peer and back, `turn:127.0.0.1:3479` by default

```
dotnet run --project src/TurnServerSample
dotnet run --project src/TurnClientSample
```
