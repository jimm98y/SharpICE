# Security

What was reviewed, what was fixed, what is left, and how the fuzzing and interoperability checks are run.

## Review

The STUN, TURN, ICE and DTLS/TLS code was reviewed against attackers who send arbitrary UDP datagrams (spoofed sources included), open arbitrary TCP/TLS connections, signal arbitrary ICE candidates, answer mDNS on the LAN, or act as a malicious server or peer. No type deserialization (BinaryFormatter, XML or JSON with type information, reflection) is used anywhere; every parser reads bytes into fixed structures.

### Fixed

| Area | Issue | Fix |
|---|---|---|
| TURN | Relays could reach services on the server's own host on any port other than its listeners (TURN SSRF); `0.0.0.0` was not refused | The host's addresses are refused on every port except those of live relays; the unspecified addresses always are; the host's addresses are re-read every minute |
| TURN | A relay's port exempted the host's address on that port for any protocol, so a TCP relay on port P opened the host's UDP service on P to UDP allocations (and a UDP relay a TCP service to Connect) | Only a live relay of the same protocol, on its own or advertised address, is exempt |
| TURN | `CreatePermission` with the client's port-0 XOR-PEER-ADDRESS was refused (403) by the default policy | A permission is judged by its address alone |
| TURN | Relay ports came from `System.Random` | Drawn from a CSPRNG (RFC 6056) |
| STUN/TURN server | A synchronous write to a TCP/TLS client that reads nothing blocked a pool thread forever | `WriteTimeout` (5 s); the connection is closed after it |
| STUN/TURN server | One host could take every TCP/TLS slot, kept alive by unauthenticated Bindings | `MaxConnectionsPerAddress` (100); `UnauthenticatedIdleTimeout` (30 s) on a server with a realm |
| STUN server | A USERHASH lookup derived a key for every user on each request | A map from each user's hash, built once |
| STUN server | 401s to spoofed sources carried SOFTWARE (amplification) | SOFTWARE is left out of errors to unauthenticated requests |
| TURN | Concurrent Allocates over many connections got past both quotas | Each reserves its slot under the lock before its sockets are bound |
| TURN | CONNECTION-IDs could be guessed one after another over one connection | A failed ConnectionBind closes its connection |
| TURN | Each relayed datagram scanned every channel under the server's lock | Channels are indexed by peer |
| TURN/STUN | Exceptions in timer callbacks (`Sweep`, DTLS idle) could end the process | Caught |
| DTLS (BouncyCastle) | After a peer's close_notify, its server thread spun at full CPU forever | The end of the queue ends the association |
| DTLS server | Idle tracking was refreshed by any datagram from the address (spoofable); stale entries closed new associations | Refreshed by decrypted records only; entries created once the association is established |
| DTLS/TLS (BouncyCastle) | Blocking handshakes and reads ran on pool threads (starvation) | Handshakes run on dedicated threads |
| TLS (BouncyCastle) | Every read and write of a connection started a new thread, so clients sending small messages caused thousands of thread creations per second | One long-lived reader thread per connection, reading ahead into a bounded buffer; writes run on the caller's thread |
| DTLS/TLS (BouncyCastle) | Clients and the server offered static-RSA or CBC suites | ECDHE with AEAD only, on both sides |
| DTLS (BouncyCastle) | An exception on the client's receive thread ended the process | Caught |
| TLS client | A server that never answered the ClientHello held the connect forever | 10 s handshake timeout |
| Certificates | No serverAuth EKU check; a malformed IP SAN threw | serverAuth required; malformed names don't match |
| STUN client | An exception in an event handler silently ended the transport's receive loop | Handlers' exceptions are caught |
| STUN client | A REALM that OpaqueString refuses threw `ArgumentException` | The challenge is ignored |
| STUN client | ALTERNATE-DOMAIN was taken from any 300 | Only from a response with MESSAGE-INTEGRITY-SHA256 |
| DNS | No name length cap; pointers could point forward (mDNS CPU/memory per packet); SRV taken from the additional section; query IDs from `System.Random` | 255-byte names, backward pointers only, answers only, CSPRNG IDs |
| ICE | Peer reflexive candidates were unbounded, and later shared one cap with signalled ones, so checks replayed from new sources could crowd out the peer's real candidates | Peer reflexive candidates have a cap of their own (16, at most `MaxRemoteCandidates`); when it is full, the oldest one with no succeeded, in-progress or nominated pair makes way |
| ICE | Incoming requests refreshed consent on a full agent; a lite agent switched to every nomination | Consent from responses only (RFC 7675); a lite agent switches only to a higher priority |
| ICE | Remote addresses that are multicast, broadcast, unspecified, mapped, scoped or non-canonical were checked | Refused, after resolution too |
| ICE | Every `.local` candidate started a resolution | Each name once, 8 at a time |
| ICE | mDNS answers were accepted from off-link sources | On-link only |
| ICE | Data was accepted from any signalled address of a pair | Only from pairs whose peer authenticated |
| ICE | Each 487 to a check flipped the current role, so several in flight made the role flap | The agent switches only if it is still in the role the check was sent in (RFC 8445 7.2.5.1) |
| ICE-TCP/TLS | An unexpected exception during a TLS handshake leaked its connection slot | Released in all cases |
| ICE-TCP | A check replayed over a connection to a passive candidate paired it, and the connection stayed open | Closed unless a check of the agent's own succeeds on it in time (a lite agent keeps it once paired) |
| ICE-TCP | Writes over a TURN TCP relay's data connection had no timeout: a peer that read nothing blocked the agent's timer, and with it every check and consent | Every ICE-TCP write is bounded by 5 s; past it the connection is closed |
| SharpDTLS | A table of fragmented ClientHellos, filled with spoofed first fragments, refused every new client | The oldest entry is evicted (SharpDTLS `main`, referenced as a project) |
| SharpDTLS | One spoofed unencrypted record (DTLS 1.2 and 1.3) ended an established association | Unencrypted records are dropped once the handshake is done; before that, malformed ones are dropped |
| SharpDTLS | Spoofed duplicate ClientHellos made a DTLS 1.3 server resend its whole flight each time (amplification) | At most one resend every 100 ms |
| SharpDTLS | Its UDP server transport started a thread for every source address, spoofed or not, and never stopped it | One receive thread; no state per source |
| SharpDTLS | A TLS client or server with no validator accepted any certificate | The chain is validated against the system trust store by default (SharpICE always sets its own validator) |
| SharpDTLS | TLS servers had no handshake timeout; `TlsStream` buffered received data without limit; small records cost quadratic time | 30 s handshake timeout and a cap on pending handshakes; at most 1 MiB buffered; linear buffering |
| SharpDTLS | Other hardening | TLS 1.2 defaults to forward-secret AEAD suites, no SHA-1 signatures, DH primes of 2048 bits; exporters need the extended master secret; a DTLS connection cap; constant-time DTLS 1.2 cookies; duplicate TLS 1.3 extensions refused; caps on empty records, warnings and ACK lists; ticket keys rotate |

### Left as they are

- **UDP reflection**: a 401 is still a few times the size of its request, as RFC 8489 specifies; rate-limit at the network if a server sees it abused.
- **Nonce replay**: nonces are stateless, bound to the source for `NonceLifetime`, as RFC 8489 allows.
- **Relayed writes**: a TURN relay writes to a TCP/TLS client synchronously; a client that reads nothing costs a thread for up to `WriteTimeout` before it is closed.
- **Per-source caps** on DTLS associations and ICE-TCP connections are not implemented; the global caps (`MaxDtlsPeers`, `MaxTcpConnections`) are.
- **TCP relay ports** are bound with address reuse, because Connect's outgoing connections are made from them; on Windows another local process could bind one too.
- **ICE-TCP over TLS** authenticates no certificate (see `IceAgentOptions.IncludeTls`).
- **Exportable keys**: DTLS, and TLS with SharpDTLS or BouncyCastle, need a certificate with an exportable private key; TLS with `TlsStacks.System` does not.
- **Replayed checks and data**: a check replayed from a new source still creates a peer reflexive candidate (within its cap) whose data is accepted, as MESSAGE-INTEGRITY does not cover the source address; DTLS on top authenticates the data itself.

## Fuzzing

`TestFuzzing` mutates well-formed inputs with bit flips, extreme lengths, truncations, insertions and splices. The inputs are STUN and TURN messages, ChannelData, ICE candidates, URIs, DNS responses, and real DTLS and TLS ClientHellos from each stack. The mutants go to the parsers, where no exception may escape, and to live listeners: STUN/TURN over UDP, TCP, TLS and DTLS with each stack, an ICE agent's UDP socket, its passive TCP/TLS candidates and its mDNS responder. Each listener must still answer a well-formed request afterwards. It runs 20,000 mutants per parser by default; for a deeper run:

```
SHARPICE_FUZZ_ITERATIONS=1000000 dotnet test src/SharpICE.Tests --filter FullyQualifiedName~TestFuzzing
```

## Interoperability

- **Chrome**: `src/SharpICE.ChromeInterop` drives a headless Chrome over its DevTools protocol, connecting an `RTCPeerConnection` with a data channel to an `IceAgent`. The scenarios cover each side offering, UDP and ICE-TCP, and mDNS names from Chrome and from SharpICE; each holds 12 s of consent checks in both directions. Run `dotnet run --project src/SharpICE.ChromeInterop [path to chrome] [scenario...]`.
- **coturn**: `TestCoturn` runs SharpTurn's client against a coturn server given in the environment. It covers UDP allocations over UDP, TCP and TLS, permissions, channels, data in both directions, and TCP allocations (RFC 6062):

```
SHARPICE_COTURN_URI=turn:192.168.1.20:3478 SHARPICE_COTURN_TLS_URI=turns:turn.example.org:5349 \
SHARPICE_COTURN_USER=user SHARPICE_COTURN_PASSWORD=pass SHARPICE_COTURN_PEER_ADDRESS=192.168.1.10 \
dotnet test src/SharpICE.Tests --filter FullyQualifiedName~TestCoturn
```

  with coturn started as, for example, `turnserver -n --lt-cred-mech --user=user:pass --realm=example.org --allowed-peer-ip=192.168.1.10 --no-cli`.
