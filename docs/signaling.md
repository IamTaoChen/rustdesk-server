# Signaling compatibility

The server supports official legacy (version 0) and version 1 key exchange. Each TCP connection gets a fresh ephemeral key. The server signs the version and ephemeral key; version 1 derives separate send/receive keys. Existing clients that do not exchange keys keep their normal non-WebRTC behavior.

TCP and WebSocket clients can register without UDP. The server sends a keep-alive every 15 seconds and removes a session after 45 seconds without incoming messages. Writes and sink-lock waits are bounded; disconnecting a registered session expires its online state if it still owns the peer's registered address.

## WebRTC

The server forwards SDP offers, answers and trickled ICE candidates. Encrypted controller sockets keep their receive cipher after their send sink moves into the routing table. Same-LAN peers use the WebRTC offer path instead of losing the offer in a local-address request.

WebRTC signaling requires the controlled peer to register over encrypted TCP or a TLS-terminated WebSocket connection. For a peer registered only over UDP or plaintext TCP, the server omits the offer and uses the normal direct/relay fallback, rather than publishing SDP/ICE over UDP. Configure those clients to use TCP/WSS registration to enable WebRTC.

WebSocket application encryption is skipped by the official client. Terminate TLS at a trusted reverse proxy and restrict access to the backend WebSocket port. The inherited upstream handling trusts forwarded-IP headers; only the proxy should be able to set them.

ICE replies must target a live punch route and come from the expected peer IP. ICE is not forwarded to arbitrary UDP addresses. Permissions and audit-context fields supplied by a controller are cleared: centralized permissions are outside this patch set, and clients must not assign themselves permissions.

## Experimental UDP and IPv6

Both extensions are off by default. Set `ENABLE_UDP_PUNCH=Y` to enable observed-port NAT replies and UDP punch replies. An initial TCP punch request must establish the route and declare the controller's UDP port. Replies must match the expected peer IP and device ID, expire after 30 seconds, and consume the route. The table holds at most 4096 routes; correlated UDP retries are limited to two. Closing the TCP connection removes its pending route. Unsolicited UDP punch requests are ignored. NAT replies contain only the observed port and have a global budget of 200 packets per second.

Set `ENABLE_IPV6_PUNCH=Y` to forward IPv6 address metadata. Only encoded IPv6 unicast addresses with a nonzero port are accepted; unspecified, multicast and link-local addresses are omitted. This does not create an IPv6 relay or verify a client's claimed IPv6 address. TCP/relay fallback remains available.

## Changing a device ID

The official client's TCP `RegisterPk` request with `old_id` can rename an existing device. The new ID follows the shared client's custom-ID rule (starts with an ASCII letter, followed by 5–15 word characters or hyphens). A matching nonempty UUID is required. The database changes only the ID in one conditional statement, preserving GUID, public key and metadata; live session/cache entries move to the new ID. Occupied IDs return `ID_EXISTS`, wrong owners return `UUID_MISMATCH`, and failed requests do not allocate a new peer.

The legacy official client sends this request without negotiated encryption. UUID ownership is the protocol's credential for this operation, not a user login. Protect the transport/network when using legacy clients. API inventory and address-book names are managed separately and are not renamed by this operation.
