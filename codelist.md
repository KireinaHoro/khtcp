# Codelist for each programming task

## Link-layer: Packet I/O On Ethernet

- Device management functions in `khtcp/include/device.h`.
- Sending/receiving Ethernet II frames functions in `khtcp/include/packetio.h`.
- Server/client model.  Server code in `khtcp/` and client code in `khtcpc/`.
  - The client and server communicates via a Unix Abstract Domain Socket (which will work independently when there are multiple network namespaces).

## Network-layer: IP Protocol

- Client side:
  - Sending/receiving IP packets functions in `khtcpc/include/ip.h`.
- Server side:
  - Sending/receiving IP packets functions in `khtcp/include/ip.h`.
  - Manual routing table manipulation functions in `khtcp/include/ip.h`.
  - Routing algorithm (RIPv2) function in `khtcp/include/rip.h` and `khtcp/src/rip.cc`.

## Transport-layer: UDP protocol

- Client side:
  - Socket-like APIs (for `SOCK_DGRAM`) provided in `khtcpc/include/socket.h`.
- Server side:
  - Sending/receiving IP packets functions in `khtcp/include/udp.h`.

## Test/Evalutaion

To test, compile both client and server code.  Run the `test_server` executable first, then run any of the test clients (you can run them concurrently) under the same network namespace.

- Server-side:
  - Arping (ARP Ping) test program has been implemented to test Ethernet II functionality.  Test program as `khtcp/tests/test_arping.cc`.
  - Test server program (direct startup, runs RIP and ARP reply) as `khtcp/tests/test_server.cc`.
- Client-side Ethernet, ARP and IP sending/receiving has been implemented to test Client-Server functionality as:
  -  `khtcpc/tests/test_eth.cc` for sending and receiving Ethernet frame
  -  `khtcpc/tests/test_arping.cc` for client-side ARPing
  -  `khtcpc/tests/test_ip.cc` for sending and receiving IP
  -  `khtcpc/tests/test_udp_send.cc` for testing SOCK_DGRAM send.
  -  `khtcpc/tests/test_udp_recv.cc` for testing SOCK_DGRAM recv.

The UDP tests shall generate packets that can be successfully delivered across the Internet (where normal UDP would work, including most NATs).