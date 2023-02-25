# Linux network fast path

In this project, we try to implement a fast path for TCP an UDP network stack
that accelerates the processing of subsequent packets of a flow once the
destination socket of the first packet (of that flow) has been identified. This
is especially beneficial for virtual overlay (encapsulated) networks that have
multiple stages (virtual devices) in its data path.

> This code is currently based on vanilla Linux kernel v5.15.

The modified files are:

* `include/linux/manish.h`: Some new structs and function declarations
* `net/core/manish.c`: Definitions of new functions
* `drivers/net/ethernet/mellanox/mlx5/core/en_rx.c`: Invoking fastpath early in datapath
* `fs/proc/stat.c`: Adding a new proc file for dynamic status/configuration
* `include/linux/skbuff.h`: Added a new member in `struct sk_buff` to store the known destination socket
* `net/core/dev.c`: Declare/initialize a per-CPU global map of flow hash to socket
* `net/core/sock.c`: Remove hashmap entry when a UDP socket is closed
* `net/ipv4/inet_connection_sock.c`: Remove hashmap entry when a TCP socket is closed
* `net/ipv4/tcp_ipv4.c`: Skip TCP socket lookup for known flows
* `net/ipv4/udp.c`: Skip UDP socket lookup for known flows


More detailed documentation coming soon... :)
