#!/usr/bin/env python3

import errno
import os
import socket
import struct
import sys
import time
import select

NP_MAGIC = 0x3158504E  # 'NPX1' little-endian

OP_PING = 0
OP_SOCKET = 1
OP_CONNECT = 2
OP_SENDTO = 3
OP_RECVFROM = 4
OP_CLOSE = 5
OP_SET_NONBLOCK = 6
OP_POLL = 7

MC_AF_INET6 = 10
MC_SOCK_STREAM = 1
MC_SOCK_DGRAM = 2
MC_SOCK_NONBLOCK = 0o00004000

MC_POLLIN = 0x0001
MC_POLLOUT = 0x0004


def read_exact(f, n: int) -> bytes:
	buf = b""
	while len(buf) < n:
		chunk = f.recv(n - len(buf))
		if not chunk:
			raise EOFError
		buf += chunk
	return buf


def write_all(f, data: bytes) -> None:
	off = 0
	while off < len(data):
		n = f.send(data[off:])
		if n <= 0:
			raise EOFError
		off += n


def pack_hdr(op: int, payload: bytes) -> bytes:
	return struct.pack("<IBBHI", NP_MAGIC, op & 0xFF, 0, 0, len(payload)) + payload


def send_resp(f, op: int, res_i64: int, extra: bytes = b""):
	payload = struct.pack("<q", res_i64) + extra
	write_all(f, pack_hdr(op | 0x80, payload))


def parse_sockaddr_in6(addr: bytes):
	# struct sockaddr_in6:
	# u16 family, u16 port(be), u32 flowinfo, 16 addr, u32 scope_id
	if len(addr) < 28:
		raise OSError(errno.EINVAL, "addrlen")
	family, port_be = struct.unpack_from("<HH", addr, 0)
	if family != MC_AF_INET6:
		raise OSError(errno.EAFNOSUPPORT, "family")
	port = struct.unpack(">H", addr[2:4])[0]
	ip = socket.inet_ntop(socket.AF_INET6, addr[8:24])
	scope_id = struct.unpack_from("<I", addr, 24)[0]
	return (ip, port, 0, scope_id)


def main(sock_path: str) -> int:
	# Wait for QEMU to create the server socket.
	for _ in range(200):
		if os.path.exists(sock_path):
			break
		time.sleep(0.02)

	cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	for _ in range(200):
		try:
			cli.connect(sock_path)
			break
		except FileNotFoundError:
			time.sleep(0.02)
		except ConnectionRefusedError:
			time.sleep(0.02)
	else:
		print(f"netproxy: could not connect to {sock_path}", file=sys.stderr)
		return 2

	next_handle = 1
	handles: dict[int, socket.socket] = {}

	try:
		while True:
			hdr = read_exact(cli, 12)
			magic, op, _r0, _r1, length = struct.unpack("<IBBHI", hdr)
			if magic != NP_MAGIC:
				return 3
			payload = read_exact(cli, length) if length else b""

			try:
				if op == OP_PING:
					send_resp(cli, op, 0)
					continue

				if op == OP_SOCKET:
					domain, stype, proto = struct.unpack("<III", payload)
					base_type = stype & 0xF
					nonblock = (stype & MC_SOCK_NONBLOCK) != 0
					if domain != MC_AF_INET6:
						raise OSError(errno.EAFNOSUPPORT, "domain")
					if base_type not in (MC_SOCK_STREAM, MC_SOCK_DGRAM):
						raise OSError(errno.EPROTONOSUPPORT, "type")
					py_type = socket.SOCK_STREAM if base_type == MC_SOCK_STREAM else socket.SOCK_DGRAM
					s = socket.socket(socket.AF_INET6, py_type, proto)
					s.setblocking(not nonblock)
					h = next_handle
					next_handle += 1
					handles[h] = s
					send_resp(cli, op, h)
					continue

				if op == OP_CONNECT:
					h, addrlen = struct.unpack_from("<II", payload, 0)
					addr = payload[8:8 + addrlen]
					s = handles.get(h)
					if not s:
						raise OSError(errno.EBADF, "handle")
					sa = parse_sockaddr_in6(addr)
					s.connect(sa)
					send_resp(cli, op, 0)
					continue

				if op == OP_SENDTO:
					(h, flags, addrlen, dlen) = struct.unpack_from("<IIII", payload, 0)
					off = 16
					addr = payload[off:off + addrlen]
					off += addrlen
					data = payload[off:off + dlen]
					s = handles.get(h)
					if not s:
						raise OSError(errno.EBADF, "handle")
					if addrlen:
						sa = parse_sockaddr_in6(addr)
					n = s.send(data) if not addrlen else s.sendto(data, sa)
					send_resp(cli, op, n)
					continue

				if op == OP_RECVFROM:
					(h, flags, maxlen) = struct.unpack("<III", payload)
					s = handles.get(h)
					if not s:
						raise OSError(errno.EBADF, "handle")
					data = s.recv(maxlen)
					send_resp(cli, op, len(data), data)
					continue

				if op == OP_CLOSE:
					(h,) = struct.unpack("<I", payload)
					s = handles.pop(h, None)
					if s:
						s.close()
					send_resp(cli, op, 0)
					continue

				if op == OP_SET_NONBLOCK:
					h, nb = struct.unpack("<II", payload)
					s = handles.get(h)
					if not s:
						raise OSError(errno.EBADF, "handle")
					s.setblocking(not bool(nb))
					send_resp(cli, op, 0)
					continue

				if op == OP_POLL:
					nfds = struct.unpack_from("<I", payload, 0)[0]
					off = 4
					items = []
					poller = select.poll()
					for _ in range(nfds):
						h, ev, _pad = struct.unpack_from("<IhH", payload, off)
						off += 8
						s = handles.get(h)
						if not s:
							raise OSError(errno.EBADF, "handle")
						mask = 0
						if ev & MC_POLLIN:
							mask |= select.POLLIN
						if ev & MC_POLLOUT:
							mask |= select.POLLOUT
						poller.register(s.fileno(), mask)
						items.append((h, s.fileno()))
					timeout_ms = struct.unpack_from("<I", payload, off)[0]
					events = poller.poll(timeout_ms)
					fd_to_mask = {fd: m for (fd, m) in events}
					extra = b""
					ready = 0
					for _h, fd in items:
						m = fd_to_mask.get(fd, 0)
						rev = 0
						if m & (select.POLLIN | select.POLLPRI):
							rev |= MC_POLLIN
						if m & select.POLLOUT:
							rev |= MC_POLLOUT
						if rev:
							ready += 1
						extra += struct.pack("<hH", rev, 0)
					send_resp(cli, op, ready, extra)
					continue

				raise OSError(errno.ENOSYS, "op")

			except (BlockingIOError, InterruptedError) as e:
				send_resp(cli, op, -int(e.errno or errno.EINPROGRESS))
			except OSError as e:
				send_resp(cli, op, -int(e.errno or errno.EIO))

	except EOFError:
		return 0
	finally:
		for s in handles.values():
			try:
				s.close()
			except Exception:
				pass
		cli.close()
	return 0


if __name__ == "__main__":
	path = sys.argv[1] if len(sys.argv) > 1 else "build/netproxy.sock"
	raise SystemExit(main(path))
