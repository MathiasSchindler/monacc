#pragma once

#include "mc_types.h"

// Minimal networking ABI for Linux x86_64 tools.
// IPv6-only for the initial nettools set.

// Address families
#define MC_AF_INET6 10

// Socket types
#define MC_SOCK_STREAM 1
#define MC_SOCK_DGRAM 2
#define MC_SOCK_RAW 3

// Socket flags (Linux)
#define MC_SOCK_NONBLOCK 00004000
#define MC_SOCK_CLOEXEC 02000000

// Protocols
#define MC_IPPROTO_TCP 6
#define MC_IPPROTO_UDP 17
#define MC_IPPROTO_ICMPV6 58

// setsockopt levels
#define MC_SOL_SOCKET 1
#define MC_IPPROTO_IPV6 41

// IPv6 socket options (subset)
#define MC_IPV6_UNICAST_HOPS 16

// fcntl
#define MC_F_GETFL 3
#define MC_F_SETFL 4

// open(2) flags reused by fcntl(F_SETFL)
#define MC_O_NONBLOCK 00004000

// poll(2)
struct mc_pollfd {
	mc_i32 fd;
	mc_i16 events;
	mc_i16 revents;
};

#define MC_POLLIN 0x0001
#define MC_POLLOUT 0x0004
#define MC_POLLERR 0x0008
#define MC_POLLHUP 0x0010

// sockaddr
struct mc_sockaddr {
	mc_u16 sa_family;
	char sa_data[14];
};

struct mc_in6_addr {
	mc_u8 s6_addr[16];
};

struct mc_sockaddr_in6 {
	mc_u16 sin6_family;   // AF_INET6
	mc_u16 sin6_port;     // network byte order
	mc_u32 sin6_flowinfo;
	struct mc_in6_addr sin6_addr;
	mc_u32 sin6_scope_id;
};
