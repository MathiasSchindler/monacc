# IPv6 network tools (nettools)

Date: 2025-12-18 (Updated)

monacc includes a set of elementary, *IPv6-only* networking tools.

The goals match the rest of the project:

- Linux x86_64 only
- syscalls first (no libc networking helpers)
- small binaries and simple, predictable behavior
- “works” beats “feature complete”
- minimize dependencies; use a library only if there is no sane syscall-only approach

---

## Rationale (why IPv6-only)

IPv6-only keeps the surface area small and avoids a bunch of legacy edge-cases:

- No dual-stack logic, no IPv4-mapped addresses, no v4 checksum/header variants
- One address format (`struct sockaddr_in6`)
- ICMP tooling can be built around ICMPv6 only
- DNS can focus on `AAAA` and `PTR` (ip6.arpa) without juggling `A`

If IPv4 support is ever desired, it can be added later as separate tools (e.g. `ping4`) or as an opt-in build flag. This document assumes **IPv6-only transport by default**.

---

## Current Status

| Tool | Status | Notes |
|------|--------|-------|
| `dns6` | ✅ Implemented | AAAA, PTR, TCP fallback |
| `ping6` | ✅ Implemented | ICMPv6 echo, hostname resolution |
| `tcp6` | ✅ Implemented | TCP connect probe with timeout |
| `wget6` | ✅ Implemented | HTTP/1.1 GET (no TLS) |
| `ntp6` | ✅ Implemented | NTP time query |
| `nc6` | ✅ Implemented | Netcat-style connect/listen |
| `trace6` | ⏳ Not yet | ICMPv6 traceroute |
| `tls13` | ✅ Implemented | TLS 1.3 client + HTTPS (separate tool) |

---

## Implemented tool set

### 1) `dns6` (DNS lookup) ✅

A tiny "dig-like" tool focused on a minimal subset:

- Default query: `AAAA <name>`
- Support `PTR <ipv6>` (reverse lookup) via `ip6.arpa` generation

CLI:

```bash
dns6 [-t aaaa|ptr] [-s SERVER] [-p PORT] [-W TIMEOUT_MS] [--tcp] NAME
```

- `dns6 example.com` → prints AAAA records
- `dns6 -t ptr 2001:db8::1` → reverse lookup
- `dns6 -s 2001:4860:4860::8888 example.com` → choose server
- `dns6 -p 53 example.com` → choose port
- `dns6 --tcp example.com` → force TCP

Behavior:

- Reads resolvers from `/etc/resolv.conf` (IPv6 only).
- Temporary fallback when no IPv6 `nameserver` exists: use Google Public DNS IPv6
   - Primary: `2001:4860:4860::8888`
   - Secondary: `2001:4860:4860::8844`
- UDP first; TCP fallback only if response is truncated (`TC` bit)
- Prints only essential output (one answer per line)

### 2) `ping6` (ICMPv6 echo) ✅

Minimal ICMPv6 echo request/reply:

CLI:

```bash
ping6 [-c COUNT] [-i INTERVAL_MS] [-W TIMEOUT_MS] [-s DNS_SERVER] HOST
```

- `ping6 2001:db8::1`
- `ping6 -c 3 -i 200 2001:db8::1` (count, interval ms)
- `ping6 -W 1000 2001:db8::1` (timeout ms)
- `ping6 -s 2001:4860:4860::8888 example.com` (specify DNS server for hostname resolution)

Behavior:

- Accepts IPv6 literals and (optionally) hostnames by doing a minimal `AAAA` lookup using the same IPv6-only resolver approach as `dns6`.
- If no IPv6 resolver exists in `/etc/resolv.conf`, require `-s DNS_SERVER`.
- Requires `CAP_NET_RAW` (or root). If not present: print a clear error and exit 2.

### 3) `trace6` (traceroute) ⏳

**Not yet implemented.**

Traceroute via ICMPv6 echo with increasing hop-limit.

CLI sketch:

- `trace6 2001:db8::1`
- `trace6 -m 30 -W 1000 2001:db8::1` (max hops, timeout ms)

Constraints:

- IPv6 literal target only for v1
- Uses ICMPv6 Time Exceeded + Echo Reply
- Requires `CAP_NET_RAW`

### 4) `tcp6` (basic TCP connect probe) ✅

A very small “can I connect” tool for IPv6:

- `tcp6 2001:db8::1 443` → exits 0 on connect, 1 on failure
- Optional: `-W <ms>` connect timeout via `poll`

This tool does **not** require raw sockets and is useful for debugging without privileges.

### 5) `wget6` (minimal HTTP GET) ✅

A tiny, syscall-only HTTP/1.1 GET client over IPv6:

- Only `http://` (no TLS)
- Connects via IPv6 only
- Supports hostname targets by resolving `AAAA` via IPv6 DNS (same resolver rules as `dns6`)

CLI sketch:

- `wget6 http://[2001:db8::1]/` (bracketed literal)
- `wget6 example.com/` (requires IPv6 resolver or `-s`)
- `wget6 -s 2001:4860:4860::8888 example.com/`
- `wget6 -O out.html example.com/`

### 6) `ntp6` (query current time) ✅

A tiny NTP client over IPv6 (UDP/123):

- Defaults to querying `pool.ntp.org`
- Supports IPv6 literals or hostnames (AAAA via `dns6`-style resolver)
- Prints the current time as Unix seconds with nanoseconds

CLI sketch:

- `ntp6` (queries `pool.ntp.org`)
- `ntp6 time.google.com`
- `ntp6 -W 1000` (timeout)

### 7) `nc6` (netcat) ✅

A minimal netcat-style tool for IPv6 TCP connections:

CLI:

```bash
nc6 [-l] [-s BIND_ADDR] [-p PORT] [-W TIMEOUT_MS] [-D DNS_SERVER] HOST PORT
nc6 -l [-s BIND_ADDR] -p PORT [-W TIMEOUT_MS]
```

- Client mode: connect to HOST:PORT
- Listen mode (`-l`): accept one connection on the given port
- Relays stdin/stdout bidirectionally

### 8) `tls13` (TLS 1.3 client) ✅

A TLS 1.3 tool supporting live HTTPS requests (see [tls.md](tls.md) for details):

CLI:

```bash
tls13 <rec|kdf|hello|hs> ...
  tls13 rec   --smoke
  tls13 kdf   --rfc8448-1rtt
  tls13 hello --rfc8448-1rtt
  tls13 hs    [-W TIMEOUT_MS] [-D DNS_SERVER] [-n SNI] [-p PATH] HOST PORT
```

Example:

```bash
tls13 hs -n en.wikipedia.org -p /api/rest_v1/page/summary/caffeine en.wikipedia.org 443
```

Note: Certificate validation is **not implemented** (no X.509 parsing in-tree).

---

## Non-goals (initial)

Not in the first iteration:

- DHCPv6, SLAAC, neighbor discovery inspection
- Netlink-heavy tools (`ip`, `ss`, `route`) — too much surface area initially
- Full DNS resolver behavior (search domains, `ndots`, DNSSEC, EDNS0, caching)
- Packet capture (`tcpdump`-like)

---

## Implementation notes (historical)

The following steps were completed during initial implementation. Kept for reference.

### Step A — Add syscall surface for networking ✅

Linux x86_64 syscalls and wrappers in `core/mc_net.h`:

1. Add syscall numbers to core/mc_syscall.h:
   - `socket` (41)
   - `connect` (42)
   - `accept` (43) (optional)
   - `sendto` (44)
   - `recvfrom` (45)
   - `setsockopt` (54)
   - `getsockopt` (55)
   - `bind` (49) (optional)
   - `close` already exists
   - `poll` (7) or `ppoll` (271) for timeouts
   - `getrandom` (318) or use time/pid for DNS IDs (see Step C)

2. Provide minimal wrappers in core (same file or a small new `core/mc_net.c` + header):
   - `mc_sys_socket(domain, type, proto)`
   - `mc_sys_connect(fd, addr, addrlen)`
   - `mc_sys_sendto(fd, buf, len, flags, addr, addrlen)`
   - `mc_sys_recvfrom(fd, buf, len, flags, addr, addrlen)`
   - `mc_sys_setsockopt(fd, level, optname, optval, optlen)`
   - `mc_sys_poll(struct pollfd*, nfds, timeout_ms)` (or `ppoll`)

3. Add minimal ABI structs/constants (no libc headers):
   - `struct sockaddr_in6`
   - `struct in6_addr`
   - `AF_INET6`, `SOCK_DGRAM`, `SOCK_STREAM`, `SOCK_RAW`
   - `IPPROTO_UDP`, `IPPROTO_TCP`, `IPPROTO_ICMPV6`
   - `IPV6_UNICAST_HOPS` / `IPV6_RECVHOPLIMIT` (for `trace6`)
   - `SOL_SOCKET`, `SO_RCVTIMEO` (optional)

All implemented in `core/mc_net.h`.

### Step B — Implement `tcp6` first ✅

Completed. Exercises socket syscalls and timeouts without needing raw sockets.

Implementation outline:

1. Parse args: `<ipv6-literal> <port>`.
2. Parse IPv6 literal:
   - Keep it strict for v1: accept full form and `::` compression.
   - Reject zone indices (`%eth0`) initially.
3. Create socket: `socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)`.
4. Optional timeout:
   - Set nonblocking (requires `fcntl`, syscall 72) OR
   - Use `poll` on `POLLOUT` after `connect` returns `EINPROGRESS`.
   - If you want to avoid `fcntl` initially, you can omit timeout v1.
5. Exit codes: `0` success, `1` failure, `2` usage.

### Step C — Implement `dns6` ✅

Completed. Implementation details:

1. Read `/etc/resolv.conf`:
   - parse lines `nameserver <ip>`
   - keep only IPv6 addresses
   - take the first one (or try each in order)

2. Build a DNS query packet manually:
   - 12-byte header
   - QNAME encoding
   - QTYPE = AAAA (28) or PTR (12)
   - QCLASS = IN (1)

3. DNS transaction ID:
   - Best: `getrandom()` if implemented
   - Acceptable fallback: `(clock_gettime_nsec ^ pid ^ stack_addr)` masked to 16-bit

4. Send UDP to port 53.
5. Receive reply; verify:
   - transaction ID matches
   - QR=1, RCODE==0
   - parse answer section for AAAA/PTR

6. TCP fallback:
   - If `TC` bit set, connect TCP/53 and retry with 2-byte length prefix framing.

Output suggestions:

- For AAAA: print each IPv6 as text
- For PTR: print hostname

### Step D — Implement `ping6` ✅

Completed. Implementation details:

1. Create raw socket: `socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)`.
2. Build ICMPv6 echo request:
   - Type 128, Code 0
   - Identifier + sequence
   - Payload: small timestamp or pattern

3. Checksum:

Linux raw ICMPv6 sockets typically require checksum to be provided by kernel for certain configurations, but don’t rely on that.

- Implement ICMPv6 checksum properly over the IPv6 pseudo-header + ICMP message.
- This requires knowing source/dest addresses; you can obtain source by connecting the socket and using `getsockname()` (syscall 51) or by letting kernel pick and using ancillary data. For v1, simplest is:
  - `connect()` the raw socket to the destination
  - call `getsockname()` to retrieve chosen source
  - compute checksum

4. RTT:
   - Use `clock_gettime(CLOCK_MONOTONIC)` before send and after receive.

5. Privileges:
   - If `socket()` returns `EPERM`, print: `ping6: need CAP_NET_RAW (try sudo)` and exit 2.

### Step E — Implement `trace6` ⏳

**Not yet implemented.** Design outline:

1. Raw ICMPv6 socket (same as ping6).
2. For hop = 1..max:
   - `setsockopt(IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hop, sizeof(hop))`
   - send echo request with unique sequence
   - receive packets until timeout:
     - Time Exceeded (Type 3) → print hop address
     - Echo Reply (Type 129) → destination reached; stop

3. Output format (simple):

- ` 1  2001:db8::a  1.2ms`
- ` 2  *`

---

## Testing strategy

### Quick manual testing

- `tcp6 ::1 22` (or any listening service)
- `dns6 example.com` (ensure `/etc/resolv.conf` has an IPv6 resolver)
- `sudo ping6 2001:4860:4860::8888`
- `sudo trace6 2001:4860:4860::8888`

### In-tree tests

Add a new test script under `tests/tools/` that is skip-friendly:

- If no IPv6 connectivity (or no resolver), skip rather than fail.
- For `ping6/trace6`: if not running as root and no CAP_NET_RAW, skip.

Recommended checks:

- `dns6` can resolve `localhost` via `::1` PTR if you implement `/etc/hosts` later; otherwise test against a known public domain.
- `tcp6 ::1 <port>` can be tested by spawning a tiny in-tree TCP server later (optional).

---

## Notes on keeping binaries small

- Avoid general-purpose parsers: keep input formats strict.
- Avoid printf-style formatting; use existing `mc_*` formatting helpers.
- Keep output stable and line-oriented.
- Implement only what is required for “basic working” v1, then iterate.

---

## Summary

The core IPv6 networking tools are implemented:

- **Completed:** `dns6`, `ping6`, `tcp6`, `wget6`, `ntp6`, `nc6`, `tls13`
- **Pending:** `trace6` (ICMPv6 traceroute)

All tools use syscalls directly, no libc networking helpers.
