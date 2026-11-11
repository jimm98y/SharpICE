# Security

What was reviewed, what was fixed, what is left, and how the fuzzing and interoperability checks are run.

## Review

The STUN, TURN, ICE and DTLS/TLS code was reviewed against attackers who send arbitrary UDP datagrams (spoofed sources included), open arbitrary TCP/TLS connections, signal arbitrary ICE candidates, answer mDNS on the LAN, or act as a malicious server or peer. No deserialization of types (BinaryFormatter, XML or JSON with type information, reflection) is used anywhere; every parser reads bytes into fixed structures.

### Fixed

| Area | Issue | Fix |
|---|---|---|
| TURN | Relays reached services of the server's own host on any port other than its listeners (TURN SSRF); `0.0.0.0` was not refused | The host's addresses are refused on every port but live relays'; the unspecified addresses always; the host's addresses are read again each minute |
| TURN | `CreatePermission` of the client's port-0 XOR-PEER-ADDRESS was refused (403) of the default policy | A permission is judged of its address alone |
| STUN/TURN server | A synchronous write to a TCP/TLS client that reads nothing blocked a pool thread forever | `WriteTimeout` (5 s); the connection is closed past it |
| STUN/TURN server | One host could take every TCP/TLS slot, kept alive by unauthenticated Bindings | `MaxConnectionsPerAddress` (100); `UnauthenticatedIdleTimeout` (30 s) of a server of a realm |
| STUN server | A USERHASH lookup derived a key of every user of each request | A map of each user's hash, made once |
| STUN server | 401s to spoofed sources carried SOFTWARE (amplification) | SOFTWARE is left out of errors to unauthenticated requests |
| TURN | Concurrent Allocates of many connections passed both quotas | Each reserves its slot under the lock before its sockets are bound |
| TURN | CONNECTION-IDs could be guessed one after another over one connection | A failed ConnectionBind closes its connection |
| TURN | Each relayed datagram scanned every channel under the server's lock | Channels are indexed of their peer |
| TURN/STUN | Exceptions in timer callbacks (`Sweep`, DTLS idle) could end the process | Guarded |
| DTLS (BouncyCastle) | After a peer's close_notify, its server thread spun at full CPU for ever | The queue's end ends the association |
| DTLS server | Idle tracking was refreshed of any datagram of the address (spoofable); stale entries closed new associations | Of decrypted records alone; entries made once established |
| DTLS/TLS (BouncyCastle) | Blocking handshakes and reads ran on pool threads (starvation) | Of threads of their own |
| DTLS/TLS (BouncyCastle) | Clients offered static-RSA and CBC suites | ECDHE with AEAD alone |
| DTLS (BouncyCastle) | An exception on the client's receive thread ended the process | Caught |
| TLS client | A server that never answered the ClientHello held the connect for ever | 10 s handshake timeout |
| Certificates | No serverAuth EKU check; a malformed IP SAN threw | serverAuth required; malformed names don't match |
| STUN client | An event handler's exception silently ended the transport's receive loop | Handlers' exceptions are caught |
| STUN client | A REALM OpaqueString refuses threw `ArgumentException` | The challenge is not taken |
| STUN client | ALTERNATE-DOMAIN was taken from any 300 | Of a response of MESSAGE-INTEGRITY-SHA256 alone |
| DNS | No name length cap; pointers could point forward (mDNS CPU/memory per packet); SRV taken of the additional section; query IDs of `System.Random` | 255-byte names, backward pointers only, answers only, CSPRNG IDs |
| ICE | Peer reflexive candidates were unbounded | Counted against `MaxRemoteCandidates` |
| ICE | Incoming requests refreshed consent of a full agent; a lite agent switched to every nomination | Consent of responses alone (RFC 7675); a lite agent switches to a higher priority alone |
| ICE | Remote addresses of multicast, broadcast, unspecified, mapped, scoped or non-canonical forms were checked | Refused, after resolution too |
| ICE | Every `.local` candidate started a resolution | Each name once, 8 at a time |
| ICE | mDNS answers were taken from off-link sources | On-link alone |
| ICE | Data was taken from any signalled address of a pair | Of pairs whose peer authenticated |
| ICE-TCP/TLS | An unexpected exception of a TLS handshake leaked its connection slot | Released in all cases |
| SharpDTLS | A table of fragmented ClientHellos, full of spoofed first fragments, refused every new client | The oldest entry is evicted (SharpDTLS `main`, after its 0.0.1 package) |

### Left as they are

- **UDP reflection**: a 401 is still a few times the size of its request, as RFC 8489 has it; rate-limit at the network if a server sees it abused.
- **Nonce replay**: nonces are stateless, bound to the source for `NonceLifetime`, as RFC 8489 allows.
- **Relayed writes**: a TURN relay writes to a TCP/TLS client synchronously; a client that reads nothing costs a thread for up to `WriteTimeout` before it is closed.
- **Per-source caps** of DTLS associations and of ICE-TCP connections are not done; the global caps (`MaxDtlsPeers`, `MaxTcpConnections`) are.
- **TCP relay ports** are bound of address reuse, as Connect's connections are made of them; on Windows another local process could bind one too.
- **ICE-TCP over TLS** authenticates no certificate (see `IceAgentOptions.IncludeTls`).
- **Exportable keys**: DTLS, and TLS of SharpDTLS or BouncyCastle, need a certificate of an exportable private key; TLS of `TlsStacks.System` does not.

## Fuzzing

`TestFuzzing` mutates well-formed inputs - STUN and TURN messages, ChannelData, ICE candidates, URIs, DNS responses, real DTLS and TLS ClientHellos of each stack - with bit flips, extreme lengths, truncations, insertions and splices, and feeds them to the parsers (no exception may escape) and to live listeners: STUN/TURN over UDP, TCP, TLS and DTLS of each stack, an ICE agent's UDP socket, passive TCP/TLS candidates and mDNS responder. Each listener must still answer a well-formed request afterwards. It runs 20,000 mutants per parser by default; deeper:

```
SHARPICE_FUZZ_ITERATIONS=1000000 dotnet test src/SharpICE.Tests --filter FullyQualifiedName~TestFuzzing
```

## Interoperability

- **Chrome**: `src/SharpICE.ChromeInterop` drives a headless Chrome over its DevTools protocol, an `RTCPeerConnection` of a data channel against an `IceAgent`: each side offering, of UDP and of ICE-TCP, of Chrome's mDNS names and of SharpICE's, each held 12 s of consent checks both ways. `dotnet run --project src/SharpICE.ChromeInterop [path to chrome] [scenario...]`.
- **coturn**: `TestCoturn` runs SharpTurn's client against a coturn of the environment's - UDP allocations of UDP, TCP and TLS, permissions, channels, data both ways, and TCP allocations (RFC 6062):

```
SHARPICE_COTURN_URI=turn:192.168.1.20:3478 SHARPICE_COTURN_TLS_URI=turns:turn.example.org:5349 \
SHARPICE_COTURN_USER=user SHARPICE_COTURN_PASSWORD=pass SHARPICE_COTURN_PEER_ADDRESS=192.168.1.10 \
dotnet test src/SharpICE.Tests --filter FullyQualifiedName~TestCoturn
```

  with coturn of e.g. `turnserver -n --lt-cred-mech --user=user:pass --realm=example.org --allowed-peer-ip=192.168.1.10 --no-cli`.
