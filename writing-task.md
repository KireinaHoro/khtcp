# Solutions to all writing tasks

## Network-layer: IP Protocol

- Solution to WT2:
  - ARP is implemented (`include/arp.h` on server and `include/arp.h` on client).  Upon receiving a IP write request, the routing table is consulted to learn the appropriate device to send to based on the destination address.  Depending on the route type,
    - If the destination is in the same subnet as the sender (i.e. `dev` type route), ARP resolution is done for the destination directly;
    - Otherwise (i.e. `via` type route), ARP resolution is done for the gateway.
  - ARP resolution is done in the following manner:
    - Upon receiving any ARP packet, record the sender IP-sender MAC mapping in the global neighbor table (a.k.a. ARP table);
      - Entries in the global neighbor table will expire after 20 seconds upon creation, and time to live will __NOT__ be refreshed when accessed.
      - If the entry being added is already present, it will be updated with the new timeout (20 seconds) and the new MAC address.
      - If the ARP opcode is Request, respond according to RFC826.
    - Consult the global neighbor table; if the requested IP address is present, return the recorded MAC;
    - Otherwise send ARP query to broadcast (`ff:ff:ff:ff:ff:ff`), requesting MAC for the requested IP address.  Then repeat the previous step (checking the neighbor table).
      - A total of 5 tries in 1 second (200ms each try) will be attempted before failing.  In case of a failure, the IP write operation fails.
  - Corner cases:
    - When a route is not present (neither directly-connected nor have gateway), a `EHOSTUNREACH` will be returned to the sending process.
    - When a route is present but the ARP resolution destination (the gateway or the direct destination) did not respond, retry will be done.
    - Routes will be checked that the gateway is on a directly-connected network when being added.
- Solution to WT3:
  - RIPv2, also known as IETF RFC2453, is implemented as the routing protocol.  The basic ideas are as follows:
    - Bellman-Ford (Distance Vector) is used as the routing algorithm
    - Supports default route distribution
    - Routes have metric of maximum 16 (aka. "infinity") and ages
      - Routes with metric infinity does not participate in data routing
      - 180 seconds before expiring (metric set to 16)
      - Deletion after 120 more seconds after expiring
    - Request / response messages:
      - Request is only generated when a router first starts up or for router inspection (not relevant here)
        - In the normal case, such requests expect a full table from neighbors
      - Response can be generated in three situations:
        - Response to Request: send full table, unicast
        - Regular Updates: runs every 30 seconds, sends full table after Split Horizon to neighbors, multicast
          - Split Horizon: when to send route into network that contains the route's gateway, poison it with metric infinity (To prevent 2-party loops)
        - Triggered Updates: runs when a route is updated, sends updated routes after Split Horizon to neighbors, multicast
          - Same split horizon definition, except that poisoned routes are not included
          - Random cooldown between 1-5 seconds to prevent flooding the network
    - Fast route acquisition, slow removal
      - Request & regular update on start, propagates to the entire network
      - No link failure detection / ICMP, can only rely on timeout to remove non-functional route
  - Corner cases:
    - Careful checks are performed to ensure neighbors behave correctly.  Malformed RIP messages will be logged then ignored.
    - Multicast IP packets (to the Local Network Control Block) will have TTL set to 1 to prevent unexpected routing of these packets.
    - Split Horizon is employed to solve cases where 2 routers form a loop.
    - Triggered Updates are employed to solve cases where 3 or more routers form a loop.
- Solution to WT4:
  - Standard compliance: works fine with RIPv2 routers: tested with BIRD.
    - Configuration file:
      ```conf
      protocol kernel {
          learn;
          ipv4 {
            export filter {
                if net = 0.0.0.0/0 then {
                    accept;
                }
                reject;
            }
          };
      }
      protocol device {
      }
      protocol rip {
          debug all;
          ipv4 {
              import filter {
                  if net = 0.0.0.0/0 then {
                      reject;
                  }
                  accept;
              };
              export all;
          };
          interface "<vnet-interface>";
      }
      ```
  - IP multicast & Ethernet multicast implemented
    - Hosts choose to join multicast group; non-present groups' messages will not be delivered
  - General UDP transport used to carry RIP
    - Hosts that do not understand RIP on port 520 will just ignore the UDP packets