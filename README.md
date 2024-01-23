# ECON: Expedited Container Overlay Network

This repo contains the code that implements ECON in the Linux kernel v5.15.
This work has been submitted to OSDI 2024.

### Abstract

> Container overlay network has become the de facto standard for container networking due to its superior flexibility, isolation, portability, and scalability. However, it suffers from performance loss compared to bare-metal host network due to prolonged critical datapath involving multiple asynchronous stages. Existing solutions—such as kernel bypass, hardware offload, packet header manipulation, and fine-grained packet steering—can improve the performance but have several practical drawbacks such as application incompatibility, protocol and scaling limitations, and security concerns. We have designed and implemented ECON (Expedited Container Overlay Network), a mechanism to reduce the critical datapath of container packets in the Linux kernel. ECON can accelerate container overlay networks to make them as fast as (in some cases, even faster than) the vanilla host network with backward-compatibility. Our solution is based on the observation that all packets of a flow follow the same redundant path in the kernel stack which can be minimized by remembering the ultimate destination of that flow and bypassing the intermediate non-critical processing stages for all subsequent packets of that flow. We show that ECON can improve container throughput by up to 121%, reduce average latency by up to 61%, and reduce the CPU usage for packet processing by up to 43% without requiring any hardware or application modification. In the case of UDP, ECON is even faster than the host network by 20%. We also discuss some minor side-effects of bypassing non-critical processing steps such as packet capture.


The modified files are:

* `include/linux/econ.h`: Some new structs and function declarations
* `net/core/econ.c`: Definitions of new functions
* `fs/proc/stat.c`: Adding a new proc file for dynamic status/configuration
* `include/linux/skbuff.h`: Added a new member in `struct sk_buff` to store the known destination socket
* `net/core/dev.c`: Declare/initialize a per-CPU global map of flow hash to socket, and socket lookup for fastpath decision
* `net/core/sock.c`: Remove hashmap entry when a UDP socket is closed
* `net/ipv4/inet_connection_sock.c`: Remove hashmap entry when a TCP socket is closed
* `net/ipv4/tcp_ipv4.c`: Skip TCP socket lookup for known flows
* `net/ipv4/udp.c`: Skip UDP socket lookup for known flows


More detailed documentation coming soon... :)
