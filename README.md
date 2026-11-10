# SharpICE
STUN, TURN and ICE written in C#, netstandard2.0 and NET10 without any native dependencies.

## SharpStunClient
A STUN client - Session Traversal Utilities for NAT [RFC8489](https://www.rfc-editor.org/rfc/rfc8489):
1. Long-term credentials: PASSWORD-ALGORITHMS, USERHASH, stale nonces, and responses checked of their integrity
1. Short-term credentials, as ICE's
1. UDP, retransmitted; TCP; TLS over it; and DTLS 1.3 and 1.2 over UDP, of [SharpDTLS](https://github.com/jimm98y/SharpDTLS): the server's certificate checked of its host name
1. ALTERNATE-SERVER and ALTERNATE-DOMAIN: a request redirected, never twice to one server
1. Unknown comprehension-required attributes: a transaction of them failed, a request of them answered with a 420
1. STUN and TURN URIs [RFC7064](https://www.rfc-editor.org/rfc/rfc7064), [RFC7065](https://www.rfc-editor.org/rfc/rfc7065), a host of no port looked up of DNS SRV [RFC2782](https://www.rfc-editor.org/rfc/rfc2782), each of its servers tried in turn
1. Test Vectors for Session Traversal Utilities for NAT (STUN) [RFC5769](https://www.rfc-editor.org/rfc/rfc5769), and RFC 8489's of SHA-256 as its erratum 6268 corrects it: what the tests check against

```cs
// a server of a URI: of its SRV records, of UDP, TCP or TLS
using var client = new StunClient(new StunClientOptions { Username = "user", Password = "pass" });
await client.ConnectAsync("stuns:stun.example.org");
IPEndPoint mapped = await client.GetMappedAddressAsync();

// any request, sent again of the credentials as the server asks for them
StunMessage response = await client.RequestAsync(new StunMessage(StunMethod.Binding, StunMessageClass.Request));

// of DTLS rather than TLS
using var dtls = new StunClient(new StunClientOptions { UseDtls = true });
await dtls.ConnectAsync("stuns:stun.example.org");

// the Binding method alone, of a socket
var server = await StunClient.ResolveAsync("stun.l.google.com:19302");
IPEndPoint address = await StunClient.GetMappedAddressAsync(server, TimeSpan.FromSeconds(3));
```

## SharpStunServer
A STUN server of the Binding method [RFC8489](https://www.rfc-editor.org/rfc/rfc8489), independent of SharpStunClient:
1. Over UDP, TCP, TLS and DTLS, each listener of its own; DTLS 1.3 and 1.2 of SharpDTLS, of a cookie exchange [RFC6347](https://www.rfc-editor.org/rfc/rfc6347), [RFC9147](https://www.rfc-editor.org/rfc/rfc9147) before any association
1. Long-term credentials, if a realm is given: the checks of RFC 8489 9.2.4 in their order, MD5 and SHA-256, USERHASH, stateless nonces of the nonce cookie and of the source, stale ones answered 438
1. ALTERNATE-SERVER and ALTERNATE-DOMAIN, of the request's source
1. Unknown comprehension-required attributes answered with a 420 - which attributes are known an option, as are the methods redirected; indications, responses and other methods dropped
1. `Process` of a transport of the caller's

Classic STUN of RFC 3489, of no magic cookie, is not answered.

```cs
var server = new StunServer(new StunServerOptions
{
    Realm = "example.org",
    Users = new Dictionary<string, string> { ["user"] = "pass" },
    Certificate = certificate, // of TLS and DTLS: of DTLS, of an exportable private key
});
server.ListenUdp(new IPEndPoint(IPAddress.Any, 3478));
server.ListenTcp(new IPEndPoint(IPAddress.Any, 3478));
server.ListenTls(new IPEndPoint(IPAddress.Any, 5349));
server.ListenDtls(new IPEndPoint(IPAddress.Any, 5349));
```

## SharpTurnClient
A TURN client - Traversal Using Relays around NAT [RFC8656](https://www.rfc-editor.org/rfc/rfc8656) - of UDP allocations, over any transport of SharpStunClient: UDP, TCP, TLS or DTLS; and of TCP allocations [RFC6062](https://www.rfc-editor.org/rfc/rfc6062), over TCP or TLS:
1. Allocate of REQUESTED-ADDRESS-FAMILY, of a dual allocation of ADDITIONAL-ADDRESS-FAMILY, of EVEN-PORT and its RESERVATION-TOKEN, of DONT-FRAGMENT and LIFETIME; SHA-256 taken of a server that lists it
1. The allocation refreshed a minute before it expires, permissions every 4 minutes, channels every 9; deleted of a Refresh of 0
1. Data to a peer of Send indications, or of ChannelData once a channel is bound - padded over a stream - a permission of its address installed first; of Data indications and ChannelData, of peers of a permission
1. TURN URIs [RFC7065](https://www.rfc-editor.org/rfc/rfc7065) and their SRV records
1. Of a TCP allocation, a connection to a peer of Connect, and one of a peer that connected of a ConnectionAttempt, each a data connection of its own of a ConnectionBind - a `Stream` of the peer's bytes as they are

```cs
using var turn = new TurnClient(new StunClientOptions { Username = "user", Password = "pass" });
await turn.ConnectAsync("turn:turn.example.org?transport=udp");
await turn.AllocateAsync();
turn.DataReceived += (s, e) => { /* e.Peer, e.Data */ };
await turn.SendAsync(peer, data);          // a permission first, then a Send indication
await turn.BindChannelAsync(peer);         // ChannelData from then on
```

A TCP allocation, over TCP or TLS to the server:

```cs
using var turn = new TurnClient(new StunClientOptions { Username = "user", Password = "pass" });
await turn.ConnectAsync("turn:turn.example.org?transport=tcp");
await turn.AllocateAsync(new TurnAllocateOptions { Tcp = true });

using var connection = await turn.ConnectPeerAsync(peer);   // the server connects to the peer
await connection.Stream.WriteAsync(data, 0, data.Length);

await turn.CreatePermissionAsync(peer.Address);              // peers of a permission may connect
turn.ConnectionAttempt += async (s, e) => { using var incoming = await turn.AcceptPeerAsync(e); /* incoming.Stream */ };
```

## SharpTurnServer
A TURN server of UDP allocations [RFC8656](https://www.rfc-editor.org/rfc/rfc8656), over the transports of SharpStunServer, and of TCP allocations [RFC6062](https://www.rfc-editor.org/rfc/rfc6062) over TCP and TLS:
1. Allocate, Refresh, CreatePermission and ChannelBind of long-term credentials, the requests of an allocation of its own user alone (441)
1. A relay of UDP of each allocation, of a port of the dynamic range at random; dual allocations, and their partial failure of ADDRESS-ERROR-CODE; EVEN-PORT and the next port reserved 30 seconds
1. Permissions of 5 minutes, channels of 10, lifetimes of the default and the maximum; an allocation of TCP or TLS ended with its connection
1. Data of the peers relayed of Data indications, or of ChannelData of a channel bound; Send indications and ChannelData of the client relayed to its peers
1. The error responses of RFC 8656 19: 403, 437, 440, 441, 442, 443, 486, 508; a retransmitted Allocate answered again
1. Safe of its defaults: a realm required, of no open relay unless asked for; peers of public unicast addresses alone - not the loopback, private, link-local or multicast ones, of `AllowPeer` otherwise - and never its own listeners; quotas of allocations, of each user and in all, and of permissions
1. TCP allocations: a relay of TCP of each, its connections to peers made of its own address and port; Connect answered of a CONNECTION-ID once the connection is made, or 446 or 447; a peer that connects of a permission told of a ConnectionAttempt, one of none closed; ConnectionBind of a new connection of the allocation's user (441), the peer's bytes relayed as they are from then on - what it sent before, kept in its socket of TCP's own window; a connection of no ConnectionBind in 30 seconds closed, each closed with the other and all with the allocation; `MaxConnectionsPerAllocation` of them at once (508)

ICMP errors are not relayed, as the system does not say which peer they are of. A TCP relay's port is bound of address reuse, as its connections to peers are made of it too: on Windows, another process of the host could bind a socket of reuse to it as well.

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
An ICE agent - Interactive Connectivity Establishment [RFC8445](https://www.rfc-editor.org/rfc/rfc8445) - of one component, RTP and RTCP multiplexed on it and all media bundled, as WebRTC has it:
1. Host candidates of the local addresses, a socket each, server reflexive ones of STUN servers, found of DNS SRV too, and relayed ones of TURN servers - of them alone, if asked to - a channel bound to the peer of a relayed pair selected
1. ICE over TCP [RFC6544](https://www.rfc-editor.org/rfc/rfc6544), if asked for: passive and active candidates, framed as [RFC4571](https://www.rfc-editor.org/rfc/rfc4571) frames them, UDP preferred; simultaneous-open is not done
1. ICE-TCP over TLS, if asked for (`IncludeTls`): candidates of TCP as above, of transport "tls", each connection of TLS 1.3 or 1.2 of SharpDTLS - the active side its client - TCP preferred over them. No standard has them, so both agents are to be SharpICE's; one that does not know them leaves them out. The TLS passes a firewall that lets TLS alone through and hides the checks; it authenticates no one, as ICE's MESSAGE-INTEGRITY and DTLS-SRTP's fingerprint do
1. The public addresses of a NAT of one to one - a cloud host's - of each socket's port: server reflexive candidates of a full agent, host candidates of a lite one
1. Candidates as SDP carries them [RFC8839](https://www.rfc-editor.org/rfc/rfc8839), and peer reflexive ones learnt of the peer's checks
1. The peer's candidates of mDNS names (".local"), as browsers hide their addresses behind, resolved of multicast DNS [RFC6762](https://www.rfc-editor.org/rfc/rfc6762); a peer reflexive candidate learnt first taking the type it is signalled of
1. Its own addresses hidden alike, if asked to: host candidates of random names it answers mDNS queries of, server reflexive ones of no related address
1. Trickled candidates and end-of-candidates [RFC8838](https://www.rfc-editor.org/rfc/rfc8838): failed at once of all the pairs failed and the peer's candidates complete
1. Checks paced and retransmitted, triggered checks, frozen foundations unfrozen as their pairs succeed, role conflicts resolved by the tie-breakers
1. Regular nomination when controlling; the nominated pair selected when controlled
1. ICE lite: a lite peer controlled, or the agent lite itself, of host candidates and no checks
1. ICE restart: new credentials, the data going by the pair selected until a new one is; a peer's restart followed
1. Consent freshness [RFC7675](https://www.rfc-editor.org/rfc/rfc7675) of the selected pair, at a random interval of 4 to 6 seconds
1. Unknown comprehension-required attributes answered with a 420
1. Every datagram that is not STUN - DTLS, RTP, RTCP [RFC7983](https://www.rfc-editor.org/rfc/rfc7983) - handed to the layers above

```cs
var agent = new IceAgent(new IceAgentOptions { Role = IceRole.Controlled });
agent.DataReceived += (s, e) => { /* DTLS, RTP, RTCP of e.Buffer, e.Offset, e.Count */ };
var candidates = await agent.GatherCandidatesAsync(); // into the session description, or trickled
agent.SetRemoteCredentials(remoteUfrag, remotePassword);
agent.AddRemoteCandidate("candidate:1 1 udp 2130706431 192.168.1.10 50000 typ host");
agent.Start();
agent.AddRemoteCandidate("a=end-of-candidates");      // the peer has no more
// once agent.State is Connected:
agent.Send(datagram, 0, datagram.Length);

// a restart of the agent's: a new offer of the new LocalUfrag, LocalPassword and the candidates
agent.Restart();
// a restart of the peer's, of the new credentials of its offer: true, and the answer of the new ones
bool restarted = agent.SetRemoteCredentials(newRemoteUfrag, newRemotePassword);
```
