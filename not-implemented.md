# Tasks not implemented

## Link-layer: Packet I/O On Ethernet

- When joining a multicast group, checks about whether the address is a valid multicast address are not performed.
  - We only join IPv4 multicast groups (for RIP), no need for the complication.
- Ethernet II checksum not implemented.
  - The sent frames may have a random CRC field of length 4.
- Ethernet minimum-length padding not implemented.
  - The sent frames may be too short for Ethernet.
- MTU-related checks not performed.
  - Reason: `pcap_sendpacket` will fail if a constructed frame was too large for the device.  Besides, as we use `getifaddrs` for getting physical address, it's not elegant to again use `ioctl` for getting the MTU of the interface.

## Network-layer: IP Protocol

- ICMP messages not implemented.
  - May be implemented in the future, not what we focus on now ("may" in RFC791).
- IP fragmenting/reassembly not implemented.
  - Per instruction as not necessary.
  - As a result, the Identification field is always left blank.
  - All packets sent have DF set.
- IP options not supported and will be ignored on receiving.
  - Per instruction as not necessary.
- Routing of multicast packets are not implemented.
  - The rules for routing IPv4 multicast are complicated and routing them rarely works.
- Not all RIPv2 options supported:
  - Next Hop and Route Tag not supported.
  - Authentication not supported.
  - RIPv1 compatibility not supported.

## Transport-layer: UDP Protocol

- UDP checksum not implemented.
  - Took too long but still can't get it right...  Optional per RFC768, so set as all zero when sending and not verified when receiving.