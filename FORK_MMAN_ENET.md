# mman/enet Fork Analysis

**Fork**: [github.com/mman/enet](https://github.com/mman/enet)
**Upstream**: [github.com/lsalzman/enet](https://github.com/lsalzman/enet)
**Analysis date**: March 2026

The fork carries approximately **1,960 lines of additions** across 18 files on top of the upstream ENet reliable UDP networking library.

---

## 1. Full IPv6 Support

The headline feature. Upstream ENet has refused multiple IPv6 pull requests over the past decade. This fork rewrites the addressing layer entirely:

- `ENetAddress.host` changes from `enet_uint32` (IPv4 only) to `struct in6_addr` (128-bit, IPv6-native). A `sin6_scope_id` field is added for link-local address support.
- DNS resolution (`enet_address_set_host`) uses `AF_UNSPEC` with `getaddrinfo` to resolve both IPv4 and IPv6, mapping IPv4 results into IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) for uniform handling.
- All socket operations in `unix.c` and `win32.c` switch from `AF_INET`/`sockaddr_in` to `AF_INET6`/`sockaddr_in6`.
- `IPV6_V6ONLY` is set to 0 on socket creation, enabling dual-stack (both IPv4 and IPv6 clients connect to the same socket).
- `IPV6_RECVPKTINFO` / `IPV6_PKTINFO` is used via `recvmsg`/`sendmsg` control messages to track the local IPv6 address on multi-homed hosts, ensuring replies go out on the same interface they arrived on. This is reflected in the new `localAddress` field on both `ENetPeer` and `ENetHost`.

## 2. BIO (Basic I/O) Abstraction Layer

An `ENetHostBIO` struct is introduced — a vtable of function pointers for all socket operations (create, bind, send, receive, wait, set_option, destroy, etc.). All internal socket calls go through this indirection:

- A default `ENET_SOCKET_BIO` is provided that maps to the standard BSD socket implementations.
- Users can supply a custom BIO via `enet_host_set_bio()` or the new parameter in `enet_host_create()`.
- Designed specifically to support Apple's Network.framework as an alternative transport (important for iOS/macOS), but also enables plugging in any custom transport.

## 3. Performance: Active Peer List & Hash-Based O(1) Lookups

Two significant performance optimizations:

- **Active peer list**: Instead of iterating all allocated peers (which could be thousands) during `enet_host_service`, the fork maintains a linked list of only the currently active/connected peers. This dramatically reduces CPU load for servers with many peer slots but few active connections.
- **uthash-based O(1) command lookup**: The fork integrates [troydhanson/uthash](https://github.com/troydhanson/uthash) and replaces linear scans of command lists with hash table lookups for `sentReliableCommands`, `incomingReliableCommands`, and `incomingUnreliableCommands`. Each command gets a packed key (e.g., `channelID << 16 | reliableSequenceNumber`) for fast matching.

## 4. Improved RTT & Retransmission Logic

Several commits refine the reliability layer:

- RTT calculations made more TCP-like (Jacobson/Karels style SRTT), fixing edge cases where SRTT < 8ms and variance was near zero.
- The retransmission timeout (RTO) lower bound adjusted to be at least 2×RTT when variance converges to small values, preventing premature retransmits on low-latency links.
- Reliable outgoing commands get more leeway to be acknowledged before being considered lost.
- Fix for excessive retransmissions when RTT variance is exactly 0.

## 5. Packet Statistics & Per-Peer MTU

- **Packet statistics**: `ENetPacket` gains fields for `queueTime`, `firstSendTime`, `ackTime`, `totalSendAttempts`, and `fragmentCount`, allowing applications to do flow control and monitor delivery performance.
- **Per-peer MTU**: `enet_host_connect` gains an extra parameter to set MTU per connection (instead of only a global host MTU).
- `reliableDataInQueue` is tracked on each peer to observe how much reliable data is buffered.

## 6. Apple / macOS / iOS / Swift Integration

- QoS socket option (`SO_NET_SERVICE_TYPE` on macOS/iOS) for traffic classification.
- A `module.modulemap` is added so the library can be imported directly as a Swift module.
- Private headers reorganized; `enet/time.h` renamed to `enet_time.h` to avoid clashing with the system `time.h`.
- Various fixes for Xcode analyzer warnings and undefined behavior sanitizer issues.

## 7. Miscellaneous

- `EINTR` handling on socket calls (returning `-2` so callers can retry).
- `SO_REUSEADDR` removed after the author realized it doesn't behave as expected for UDP.
- `connectID` is preserved on peer reset (available after disconnect).
- `enet_host_fetch()` added as a new API entry point.
- `void * data` and `void * connection` app-private fields added to both `ENetHost` and `ENetPeer`.

---

## API Breaking Changes

The fork introduces several API-breaking changes relative to upstream:

| Change | Details |
|--------|---------|
| `enet_host_create` | New `ENetHostBIO` parameter added |
| `enet_host_connect` | New MTU parameter added |
| `ENetAddress.host` | Changed from `enet_uint32` to `struct in6_addr` |
| `enet_socket_send` / `enet_socket_receive` | Signatures changed to include source/local address and opaque context pointer |
| `ENetPeer.address` | Split into `peerAddress` and `localAddress` |
| `ENetHost.receivedAddress` | Split into `peerAddress` and `localAddress` |

## Wire Compatibility

The fork does **not** change the ENet wire protocol. IPv4 upstream clients can connect to a mman/enet server (and vice versa) as long as the server is running in dual-stack mode. The changes are confined to the socket/addressing layer and internal data structures.
