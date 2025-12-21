#pragma once

#include "mc_types.h"

#if defined(__APPLE__) && defined(__MACH__)
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <fcntl.h>
#endif

// Minimal networking ABI for Linux x86_64 tools.
// IPv6-only for the initial nettools set.

// Address families
#if defined(__APPLE__) && defined(__MACH__)
#define MC_AF_INET6 AF_INET6
#else
#define MC_AF_INET6 10
#endif

// Socket types
#if defined(__APPLE__) && defined(__MACH__)
#define MC_SOCK_STREAM SOCK_STREAM
#define MC_SOCK_DGRAM SOCK_DGRAM
#define MC_SOCK_RAW SOCK_RAW
#else
#define MC_SOCK_STREAM 1
#define MC_SOCK_DGRAM 2
#define MC_SOCK_RAW 3
#endif

// Socket flags
#if defined(__APPLE__) && defined(__MACH__)
#if defined(SOCK_NONBLOCK)
#define MC_SOCK_NONBLOCK SOCK_NONBLOCK
#else
#define MC_SOCK_NONBLOCK 0
#endif
#if defined(SOCK_CLOEXEC)
#define MC_SOCK_CLOEXEC SOCK_CLOEXEC
#else
#define MC_SOCK_CLOEXEC 0
#endif
#else
// Linux values
#define MC_SOCK_NONBLOCK 00004000
#define MC_SOCK_CLOEXEC 02000000
#endif

// Protocols
#if defined(__APPLE__) && defined(__MACH__)
#define MC_IPPROTO_TCP IPPROTO_TCP
#define MC_IPPROTO_UDP IPPROTO_UDP
#define MC_IPPROTO_ICMPV6 IPPROTO_ICMPV6
#else
#define MC_IPPROTO_TCP 6
#define MC_IPPROTO_UDP 17
#define MC_IPPROTO_ICMPV6 58
#endif

// setsockopt levels
#if defined(__APPLE__) && defined(__MACH__)
#define MC_SOL_SOCKET SOL_SOCKET
#define MC_IPPROTO_IPV6 IPPROTO_IPV6
#else
#define MC_SOL_SOCKET 1
#define MC_IPPROTO_IPV6 41
#endif

// SOL_SOCKET options (subset)
#if defined(__APPLE__) && defined(__MACH__)
#define MC_SO_REUSEADDR SO_REUSEADDR
#define MC_SO_ERROR SO_ERROR
#else
#define MC_SO_REUSEADDR 2
#define MC_SO_ERROR 4
#endif

// IPv6 socket options (subset)
#if defined(__APPLE__) && defined(__MACH__)
#define MC_IPV6_UNICAST_HOPS IPV6_UNICAST_HOPS
#else
#define MC_IPV6_UNICAST_HOPS 16
#endif

// fcntl
#if defined(__APPLE__) && defined(__MACH__)
#define MC_F_GETFL F_GETFL
#define MC_F_SETFL F_SETFL
#else
#define MC_F_GETFL 3
#define MC_F_SETFL 4
#endif

// open(2) flags reused by fcntl(F_SETFL)
#if defined(__APPLE__) && defined(__MACH__)
#define MC_O_NONBLOCK O_NONBLOCK
#else
#define MC_O_NONBLOCK 00004000
#endif

// shutdown(2)
#define MC_SHUT_RD 0
#define MC_SHUT_WR 1
#define MC_SHUT_RDWR 2

// poll(2)
struct mc_pollfd {
	mc_i32 fd;
	mc_i16 events;
	mc_i16 revents;
};

#if defined(__APPLE__) && defined(__MACH__)
#define MC_POLLIN POLLIN
#define MC_POLLOUT POLLOUT
#define MC_POLLERR POLLERR
#define MC_POLLHUP POLLHUP
#else
#define MC_POLLIN 0x0001
#define MC_POLLOUT 0x0004
#define MC_POLLERR 0x0008
#define MC_POLLHUP 0x0010
#endif


// sockaddr
struct mc_sockaddr {
	mc_u16 sa_family;
	char sa_data[14];
};

#if defined(__APPLE__) && defined(__MACH__)
#if defined(s6_addr)
#undef s6_addr
#endif
#endif

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
