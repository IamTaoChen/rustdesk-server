# Signaling compatibility

The server supports official legacy (version 0) and version 1 key exchange. Each TCP connection gets a fresh ephemeral key. The server signs the version and ephemeral key; version 1 derives separate send/receive keys. Existing clients that do not exchange keys keep their normal non-WebRTC behavior.

TCP and WebSocket clients can register without UDP. The server sends a keep-alive every 15 seconds and removes a session after 45 seconds without incoming messages. Writes and sink-lock waits are bounded; disconnecting a registered session expires its online state if it still owns the peer's registered address.

## WebRTC

The server forwards SDP offers, answers and trickled ICE candidates. Encrypted controller sockets keep their receive cipher after their send sink moves into the routing table. Same-LAN peers use the WebRTC offer path instead of losing the offer in a local-address request.

WebRTC signaling requires the controlled peer to register over encrypted TCP or a TLS-terminated WebSocket connection. For a peer registered only over UDP or plaintext TCP, the server omits the offer and uses the normal direct/relay fallback, rather than publishing SDP/ICE over UDP. Configure those clients to use TCP/WSS registration to enable WebRTC.

WebSocket application encryption is skipped by the official client. Terminate TLS at a trusted reverse proxy and restrict access to the backend WebSocket port. The inherited upstream handling trusts forwarded-IP headers; only the proxy should be able to set them.

ICE replies must target a live punch route and come from the expected peer IP. ICE is not forwarded to arbitrary UDP addresses. Permissions and audit-context fields supplied by a controller are cleared: centralized permissions are outside this patch set, and clients must not assign themselves permissions.
