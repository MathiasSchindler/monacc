#ifndef NET_H
#define NET_H

#include <stdint.h>

// netproxy-backed sockets (host proxy over COM2)

int netproxy_is_ready(void);
int netproxy_ensure_ready(void);

int64_t netproxy_socket(uint32_t domain, uint32_t type, uint32_t proto);
int64_t netproxy_connect(uint32_t handle, const void *addr, uint32_t addrlen);
int64_t netproxy_sendto(uint32_t handle, const void *buf, uint32_t len, uint32_t flags, const void *addr, uint32_t addrlen);
int64_t netproxy_recvfrom(uint32_t handle, void *buf, uint32_t len, uint32_t flags);
int64_t netproxy_close(uint32_t handle);
int64_t netproxy_set_nonblock(uint32_t handle, int nonblock);
int64_t netproxy_poll(const uint32_t *handles, const int16_t *events, int16_t *revents, uint32_t nfds, int32_t timeout_ms);

#endif
