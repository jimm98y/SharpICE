# SharpICE
STUN, TURN and ICE written in C#, netstandard2.0 and NET10 without any native dependencies.

## SharpStunClient
STUN messages and a STUN client:
1. Session Traversal Utilities for NAT (STUN) [RFC8489](https://www.rfc-editor.org/rfc/rfc8489): messages of every method and class, their attributes, MESSAGE-INTEGRITY and FINGERPRINT
1. Test Vectors for Session Traversal Utilities for NAT (STUN) [RFC5769](https://www.rfc-editor.org/rfc/rfc5769): what the tests check against
1. A client of the Binding method: the address a NAT maps a socket to

```cs
var server = await StunClient.ResolveAsync("stun.l.google.com:19302");
IPEndPoint mapped = await StunClient.GetMappedAddressAsync(server, TimeSpan.FromSeconds(3));
```

## SharpTurnClient
A TURN client - Traversal Using Relays around NAT [RFC8656](https://www.rfc-editor.org/rfc/rfc8656). To be done.

## SharpICE
An ICE agent - Interactive Connectivity Establishment [RFC8445](https://www.rfc-editor.org/rfc/rfc8445) - of one component, RTP and RTCP multiplexed on it and all media bundled, as WebRTC has it:
1. Host candidates of the local addresses, a socket each, and server reflexive ones of STUN servers
1. Candidates as SDP carries them [RFC8839](https://www.rfc-editor.org/rfc/rfc8839), and peer reflexive ones learnt of the peer's checks
1. Checks paced and retransmitted, triggered checks, role conflicts resolved by the tie-breakers
1. Regular nomination when controlling; the nominated pair selected when controlled
1. Consent freshness [RFC7675](https://www.rfc-editor.org/rfc/rfc7675) of the selected pair
1. Every datagram that is not STUN - DTLS, RTP, RTCP [RFC7983](https://www.rfc-editor.org/rfc/rfc7983) - handed to the layers above

```cs
var agent = new IceAgent(new IceAgentOptions { Role = IceRole.Controlled });
agent.DataReceived += (s, e) => { /* DTLS, RTP, RTCP of e.Buffer, e.Offset, e.Count */ };
var candidates = await agent.GatherCandidatesAsync(); // into the session description, or trickled
agent.SetRemoteCredentials(remoteUfrag, remotePassword);
agent.AddRemoteCandidate("candidate:1 1 udp 2130706431 192.168.1.10 50000 typ host");
agent.Start();
// once agent.State is Connected:
agent.Send(datagram, 0, datagram.Length);
```
