# SharpICE
STUN, TURN and ICE written in C#, netstandard2.0 and NET10 without any native dependencies.

## SharpStunClient
STUN messages and a STUN client:
1. Session Traversal Utilities for NAT (STUN) [RFC8489](https://www.rfc-editor.org/rfc/rfc8489): messages of every method and class, their attributes, MESSAGE-INTEGRITY, MESSAGE-INTEGRITY-SHA256 and FINGERPRINT
1. Long-term credentials: the MD5 and SHA-256 keys, PASSWORD-ALGORITHMS, USERHASH, the nonce cookie's security features, stale nonces, and responses checked of their integrity
1. Short-term credentials, as ICE's
1. UDP, retransmitted; TCP; TLS over it; and DTLS over UDP, of BouncyCastle: the server's certificate checked of its host name
1. ALTERNATE-SERVER and ALTERNATE-DOMAIN: a request redirected, never twice to one server
1. Unknown comprehension-required attributes: a transaction of them failed, a request of them answered with a 420
1. STUN and TURN URIs [RFC7064](https://www.rfc-editor.org/rfc/rfc7064), [RFC7065](https://www.rfc-editor.org/rfc/rfc7065), a host of no port looked up of DNS SRV [RFC2782](https://www.rfc-editor.org/rfc/rfc2782), each of its servers tried in turn
1. Test Vectors for Session Traversal Utilities for NAT (STUN) [RFC5769](https://www.rfc-editor.org/rfc/rfc5769), and RFC 8489's of SHA-256 as its erratum 6268 corrects it: what the tests check against

```cs
// a server of a URI: of its SRV records, of UDP, TCP or TLS
using var client = await StunClient.ConnectAsync("stuns:stun.example.org", new StunClientOptions { Username = "user", Password = "pass" });
IPEndPoint mapped = await client.GetMappedAddressAsync();

// any request, sent again of the credentials as the server asks for them
StunMessage response = await client.RequestAsync(new StunMessage(StunMethod.Binding, StunMessageClass.Request));

// of DTLS rather than TLS
using var dtls = await StunClient.ConnectAsync("stuns:stun.example.org", new StunClientOptions { UseDtls = true });

// the Binding method alone, of a socket
var server = await StunClient.ResolveAsync("stun.l.google.com:19302");
IPEndPoint address = await StunClient.GetMappedAddressAsync(server, TimeSpan.FromSeconds(3));
```

## SharpStunServer
A STUN server of the Binding method [RFC8489](https://www.rfc-editor.org/rfc/rfc8489):
1. Over UDP, TCP, TLS and DTLS, each listener of its own; DTLS of a cookie exchange [RFC6347](https://www.rfc-editor.org/rfc/rfc6347) before any association
1. Long-term credentials, if a realm is given: the checks of RFC 8489 9.2.4 in their order, MD5 and SHA-256, USERHASH, stateless nonces of the nonce cookie and of the source, stale ones answered 438
1. ALTERNATE-SERVER and ALTERNATE-DOMAIN, of the request's source
1. Unknown comprehension-required attributes answered with a 420; indications, responses and other methods dropped
1. `Process` of a transport of the caller's

Classic STUN of RFC 3489, of no magic cookie, is not answered. A DTLS ClientHello fragmented into several records - as OpenSSL sends one when it cannot learn the path's MTU - is not taken, as BouncyCastle's cookie exchange does not reassemble it.

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
A TURN client - Traversal Using Relays around NAT [RFC8656](https://www.rfc-editor.org/rfc/rfc8656). To be done.

## SharpICE
An ICE agent - Interactive Connectivity Establishment [RFC8445](https://www.rfc-editor.org/rfc/rfc8445) - of one component, RTP and RTCP multiplexed on it and all media bundled, as WebRTC has it:
1. Host candidates of the local addresses, a socket each, and server reflexive ones of STUN servers, found of DNS SRV too
1. ICE over TCP [RFC6544](https://www.rfc-editor.org/rfc/rfc6544), if asked for: passive and active candidates, framed as [RFC4571](https://www.rfc-editor.org/rfc/rfc4571) frames them, UDP preferred; simultaneous-open is not done
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
