### XDP-Based Anti-DDoS Protection
#### Introduction

This is a lightweight XDP-based anti-DDoS protection system I developed a few years ago to mitigate the impact of SYN floods and UDP flood attacks using rate limiting. By leveraging the power of XDP, this approach provides efficient packet filtering by avoiding the overhead from the network stack and all buffers operations on `sk_buff`.

For more information, please take a look at the white paper: The eXpress Data Path: Fast Programmable Packet Processing in the Operating System Kernel.

> [!CAUTION]
> This program is provided as a reference implementation. I strongly recommend adapting it to your specific needs before deploying it in production.


#### Usage
Depending on your NIC, choose the appropriate XDP execution mode:
- Offloaded: The eBPF program will be loaded in your SmartNIC
- Native Mode: The eBPF program will used your NIC driver hook.
- Generic (Skb): Integrate the eBPF program in the kernel network stack (avoid if possible for performance reasons).

To load the XDP program and attach it to an interface, you can use tools such as `ip`.