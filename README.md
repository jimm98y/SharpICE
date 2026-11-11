# SharpICE
STUN, TURN and ICE in C#, with no native dependencies. The libraries target netstandard2.0, .NET Framework 4.7.2, .NET 8 and .NET 10.

There are three libraries:

| Library | What it is |
|---|---|
| SharpStun | A STUN client and server |
| SharpTurn | A TURN client and server, built on SharpStun |
| SharpICE | An ICE agent, built on SharpStun and SharpTurn |

DTLS and TLS come from [SharpDTLS](https://github.com/jimm98y/SharpDTLS) by default. You can switch to BouncyCastle, or for TLS to .NET's `SslStream`.

## SharpStun
### Client
A STUN client ([RFC 8489](https://www.rfc-editor.org/rfc/rfc8489)).

- **Credentials**:
  - Long-term credentials: PASSWORD-ALGORITHMS, USERHASH, stale nonces, and integrity checks on every response.
  - Short-term credentials, as ICE uses them.
- **Transports**:
  - UDP (with retransmissions), TCP, TLS and DTLS.
  - Over TLS and DTLS, the server's certificate is checked against its host name.
- **DTLS stack** (`DtlsStack`): SharpDTLS (the default) for DTLS 1.3 and 1.2, or BouncyCastle for DTLS 1.2.
- **TLS stack** (`TlsStack`): SharpDTLS (the default) for TLS 1.3 and 1.2, BouncyCastle for TLS 1.2, or .NET's `SslStream`.
- **Redirects**: ALTERNATE-SERVER and ALTERNATE-DOMAIN are followed. The client never goes to the same server twice.
- **Unknown attributes**: if a response has an unknown comprehension-required attribute, the transaction fails.
- **URIs and DNS**:
  - STUN and TURN URIs ([RFC 7064](https://www.rfc-editor.org/rfc/rfc7064), [RFC 7065](https://www.rfc-editor.org/rfc/rfc7065)).
  - A host without a port is looked up with DNS SRV ([RFC 2782](https://www.rfc-editor.org/rfc/rfc2782)), and each server it returns is tried in turn.
- **Tested** against the test vectors of [RFC 5769](https://www.rfc-editor.org/rfc/rfc5769), and the SHA-256 vectors of RFC 8489 (as corrected by erratum 6268).

```cs
// Connect to a server by URI. Uses SRV records, and UDP, TCP or TLS.
using var client = new StunClient(new StunClientOptions { Username = "user", Password = "pass" });
await client.ConnectAsync("stuns:stun.example.org");
IPEndPoint mapped = await client.GetMappedAddressAsync();

// Send any request. If the server asks for credentials, the client sends it again with them.
StunMessage response = await client.RequestAsync(new StunMessage(StunMethod.Binding, StunMessageClass.Request));

// Use DTLS instead of TLS: SharpDTLS by default, or BouncyCastle.
using var dtls = new StunClient(new StunClientOptions { UseDtls = true });
await dtls.ConnectAsync("stuns:stun.example.org");
using var bc = new StunClient(new StunClientOptions { UseDtls = true, DtlsStack = DtlsStacks.BouncyCastle });

// Just a Binding request, without a client object.
var server = await StunClient.ResolveAsync("stun.l.google.com:19302");
IPEndPoint address = await StunClient.GetMappedAddressAsync(server, TimeSpan.FromSeconds(3));
```

### Server
A STUN server for the Binding method ([RFC 8489](https://www.rfc-editor.org/rfc/rfc8489)).

- **Listeners**: UDP, TCP, TLS and DTLS, each on its own listener.
- **DTLS**:
  - A cookie exchange runs before any connection is set up ([RFC 6347](https://www.rfc-editor.org/rfc/rfc6347), [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147)).
  - The stack is set by `DtlsStack`: SharpDTLS (the default) for DTLS 1.3 and 1.2, or BouncyCastle for DTLS 1.2.
- **TLS**:
  - The stack is set by `TlsStack`: SharpDTLS by default.
  - With SharpDTLS or BouncyCastle, the certificate's private key must be exportable. With `SslStream` it doesn't have to be.
- **Long-term credentials**, when you set a realm:
  - Requests are checked in the order RFC 8489 section 9.2.4 gives.
  - MD5 and SHA-256, and USERHASH.
  - Nonces are stateless and tied to the client's address. A stale one gets a 438.
- **Redirects**: ALTERNATE-SERVER and ALTERNATE-DOMAIN, chosen by the request's source.
- **Unknown attributes**: a request with an unknown comprehension-required attribute gets a 420. You can set which attributes are known.
- **Dropped**: indications, responses and unsupported methods.
- **Your own transport**: `Process` handles a message from a transport you manage.

Classic STUN (RFC 3489, without the magic cookie) gets no answer.

```cs
var server = new StunServer(new StunServerOptions
{
    Realm = "example.org",
    Users = new Dictionary<string, string> { ["user"] = "pass" },
    Certificate = certificate, // needed for TLS and DTLS; for DTLS the private key must be exportable
});
server.ListenUdp(new IPEndPoint(IPAddress.Any, 3478));
server.ListenTcp(new IPEndPoint(IPAddress.Any, 3478));
server.ListenTls(new IPEndPoint(IPAddress.Any, 5349));
server.ListenDtls(new IPEndPoint(IPAddress.Any, 5349));
```

## SharpTurn
### Client
A TURN client ([RFC 8656](https://www.rfc-editor.org/rfc/rfc8656)). It supports two kinds of allocation:
- UDP allocations, over UDP, TCP, TLS or DTLS.
- TCP allocations ([RFC 6062](https://www.rfc-editor.org/rfc/rfc6062)), over TCP or TLS.

Its features:
- **Allocate options**:
  - REQUESTED-ADDRESS-FAMILY, and dual-stack allocations with ADDITIONAL-ADDRESS-FAMILY.
  - EVEN-PORT with RESERVATION-TOKEN, DONT-FRAGMENT and LIFETIME.
  - SHA-256 when the server offers it.
- **Refreshes**:
  - The allocation is refreshed a minute before it expires, permissions every 4 minutes, and channels every 9 minutes.
  - A Refresh with a lifetime of 0 deletes the allocation.
- **Sending data**:
  - A permission for the peer's address is installed first.
  - Data goes out in Send indications, or as ChannelData once a channel is bound.
  - ChannelData is padded over TCP and TLS.
- **Receiving data**: Data indications and ChannelData are accepted only from peers that have a permission.
- **URIs**: TURN URIs ([RFC 7065](https://www.rfc-editor.org/rfc/rfc7065)) and their SRV records.
- **TCP allocations**:
  - Connect opens a connection to a peer.
  - A ConnectionAttempt tells you a peer has connected to you.
  - Each peer connection gets its own data connection, set up with ConnectionBind, and you get it as a plain `Stream` of the peer's bytes.

```cs
using var turn = new TurnClient(new StunClientOptions { Username = "user", Password = "pass" });
await turn.ConnectAsync("turn:turn.example.org?transport=udp");
await turn.AllocateAsync();
turn.DataReceived += (s, e) => { /* e.Peer; the data is e.Buffer, e.Offset, e.Count */ };
await turn.SendAsync(peer, data);          // installs a permission, then sends a Send indication
await turn.BindChannelAsync(peer);         // ChannelData from now on
```

A TCP allocation, over TCP or TLS to the server:

```cs
using var turn = new TurnClient(new StunClientOptions { Username = "user", Password = "pass" });
await turn.ConnectAsync("turn:turn.example.org?transport=tcp");
await turn.AllocateAsync(new TurnAllocateOptions { Tcp = true });

using var connection = await turn.ConnectPeerAsync(peer);   // the server connects to the peer
await connection.Stream.WriteAsync(data, 0, data.Length);

await turn.CreatePermissionAsync(peer.Address);              // peers with a permission may connect to you
turn.ConnectionAttempt += async (s, e) => { using var incoming = await turn.AcceptPeerAsync(e); /* incoming.Stream */ };
```

### Server
A TURN server for UDP allocations ([RFC 8656](https://www.rfc-editor.org/rfc/rfc8656)) over any of the STUN server's transports, and for TCP allocations ([RFC 6062](https://www.rfc-editor.org/rfc/rfc6062)) over TCP and TLS.

- **Requests**:
  - Allocate, Refresh, CreatePermission and ChannelBind, all with long-term credentials.
  - Only the user who made an allocation can use it (otherwise 441).
- **UDP relays**:
  - Each allocation gets its own relay port, chosen at random from the dynamic range.
  - Dual-stack allocations are supported. When one address family fails, ADDRESS-ERROR-CODE says so.
  - EVEN-PORT reserves the next port for 30 seconds.
- **Lifetimes**:
  - Permissions last 5 minutes and channels 10 minutes.
  - Allocations have a default and a maximum lifetime.
  - An allocation made over TCP or TLS ends when its connection closes.
- **Relaying**:
  - Data from peers goes to the client in Data indications, or as ChannelData on a bound channel.
  - Send indications and ChannelData from the client go to its peers.
- **Errors**:
  - The error responses of RFC 8656 section 19: 403, 437, 440, 441, 442, 443, 486 and 508.
  - A retransmitted Allocate gets the same answer again.
- **Safe defaults**:
  - A realm is required. It isn't an open relay unless you ask for one.
  - Peers must have public unicast addresses. Loopback, private, link-local and multicast addresses are refused unless you allow them with `AllowPeer`. The server's own host is always refused, except its relay ports.
  - Allocations are limited per user and in total, and so are permissions.
- **TCP allocations**:
  - Each allocation gets a TCP relay. Connections to peers are made from its address and port.
  - Connect returns a CONNECTION-ID once the connection is up, or 446 or 447.
  - A peer with a permission that connects is announced with a ConnectionAttempt. A peer without one is closed.
  - ConnectionBind on a new connection, by the allocation's user (otherwise 441), joins it to the peer. From then on the bytes are relayed unchanged, including what the peer sent before.
  - A peer connection without a ConnectionBind within 30 seconds is closed.
  - When either connection closes, so does the other, and all of them close with the allocation.
  - At most `MaxConnectionsPerAllocation` connections at once (otherwise 508).

ICMP errors are not relayed, because the system does not say which peer they came from. A TCP relay port is bound with address reuse, because the connections to peers are made from it. On Windows this means another process on the same host could bind that port too.

```cs
var server = new TurnServer(new TurnServerOptions
{
    Stun = new StunServerOptions { Realm = "example.org", Users = new Dictionary<string, string> { ["user"] = "pass" }, AuthenticateBinding = false },
    RelayAddress = IPAddress.Parse("203.0.113.7"),
});
server.ListenUdp(new IPEndPoint(IPAddress.Any, 3478));
server.ListenTcp(new IPEndPoint(IPAddress.Any, 3478));
```

## SharpICE
An ICE agent ([RFC 8445](https://www.rfc-editor.org/rfc/rfc8445)) with one component, as WebRTC uses it: RTP and RTCP are multiplexed and all media is bundled.

- **Candidates**:
  - Host candidates from the local addresses, with a socket for each.
  - Server reflexive candidates from STUN servers (found with DNS SRV too).
  - Relayed candidates from TURN servers. You can use relayed candidates only, if you want. When a relayed pair is selected, a channel is bound to the peer.
- **ICE over TCP** ([RFC 6544](https://www.rfc-editor.org/rfc/rfc6544)), if you turn it on (`IncludeTcp`):
  - Passive and active candidates, framed as [RFC 4571](https://www.rfc-editor.org/rfc/rfc4571) describes. UDP is preferred.
  - Simultaneous-open is not supported.
- **Relayed ICE-TCP candidates**, when ICE over TCP is on:
  - Each TURN server reached over TCP or TLS gets a TCP allocation ([RFC 6062](https://www.rfc-editor.org/rfc/rfc6062)).
  - The passive candidate is the relayed address, and each of the peer's candidate addresses gets a permission. The active candidate uses Connect.
  - When both sides use relays on the same server, the one with the lower port connects.
- **1:1 NAT**, such as a cloud host's public address (`PublicAddresses`): a full agent uses it for server reflexive candidates, a lite agent for host candidates.
- **SDP**: candidates in the format SDP uses ([RFC 8839](https://www.rfc-editor.org/rfc/rfc8839)). Peer reflexive candidates are learnt from the peer's checks.
- **mDNS**:
  - Browsers hide their addresses behind ".local" names. These are resolved with multicast DNS ([RFC 6762](https://www.rfc-editor.org/rfc/rfc6762)).
  - If a peer reflexive candidate was learnt first, it takes the type the peer signals later.
  - You can hide your own addresses the same way (`MdnsCandidates`): host candidates get random names that the agent answers mDNS queries for, and server reflexive candidates don't show the related address.
- **Trickle ICE** and end-of-candidates ([RFC 8838](https://www.rfc-editor.org/rfc/rfc8838)): once every pair has failed and the peer has sent all its candidates, the agent fails straight away.
- **Checks**:
  - Paced and retransmitted, with triggered checks.
  - Frozen foundations are unfrozen as their pairs succeed.
  - Role conflicts are resolved with the tie-breakers.
- **Nomination**: regular nomination when controlling. When controlled, the agent selects the pair the peer nominates.
- **ICE lite**: a lite peer is always controlled. The agent can also be lite itself (`Lite`): it then has host candidates only and sends no checks.
- **ICE restart**: new credentials. Data keeps using the selected pair until a new one is chosen. The agent also follows the peer's restarts.
- **Consent freshness** ([RFC 7675](https://www.rfc-editor.org/rfc/rfc7675)) on the selected pair, at a random interval of 4 to 6 seconds.
- **Unknown attributes**: a request with an unknown comprehension-required attribute gets a 420.
- **Other traffic**: every datagram that is not STUN (DTLS, RTP or RTCP, see [RFC 7983](https://www.rfc-editor.org/rfc/rfc7983)) is passed up to your code.

```cs
var options = new IceAgentOptions { Role = IceRole.Controlled };
options.StunServers.Add("stun:stun.l.google.com:19302");
options.TurnServers.Add(new IceTurnServer { Uri = "turn:turn.example.org", Username = "user", Password = "pass" });
var agent = new IceAgent(options);
agent.DataReceived += (s, e) => { /* DTLS, RTP or RTCP in e.Buffer, e.Offset, e.Count */ };
var candidates = await agent.GatherCandidatesAsync(); // put them in the session description, or trickle them
agent.SetRemoteCredentials(remoteUfrag, remotePassword);
agent.AddRemoteCandidate("candidate:1 1 udp 2130706431 192.168.1.10 50000 typ host");
agent.Start();
agent.AddRemoteCandidate("a=end-of-candidates");      // the peer has no more candidates
// once agent.State is Connected:
agent.Send(datagram, 0, datagram.Length);

// Restart from your side: send a new offer with the new LocalUfrag, LocalPassword and candidates.
agent.Restart();
// The peer restarted: pass the new credentials from its offer. Returns true, and you answer with your new ones.
bool restarted = agent.SetRemoteCredentials(newRemoteUfrag, newRemotePassword);
```

## Samples
The samples run against each other on one machine with their default settings:

| Sample | What it does |
|---|---|
| `StunServerSample [port]` | A STUN server on UDP and TCP, IPv4 and IPv6. Default port 3478. |
| `StunClientSample [uri] [username] [password]` | Shows the address a STUN server sees you at. Default `stun:127.0.0.1:3478`. |
| `TurnServerSample [port] [username] [password] [realm] [relayAddress]` | A TURN server with UDP and TCP relays. Default port 3479, user `user`, password `pass`. |
| `TurnClientSample [uri] [username] [password] [peer]` | Allocates a relay and sends data through it to an echo peer and back. Default `turn:127.0.0.1:3479`. |

```
dotnet run --project src/TurnServerSample
dotnet run --project src/TurnClientSample
```
