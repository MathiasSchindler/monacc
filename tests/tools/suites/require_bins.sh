#!/bin/sh
set -eu

BIN=${1:?usage: require_bins.sh /path/to/sysbox/bin}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

require_bin() {
  [ -x "$BIN/$1" ] || fail "missing $BIN/$1 (build first)"
}

# Core tools expected by tests.
require_bin rm
require_bin cp
require_bin mkdir
require_bin rmdir
require_bin echo
require_bin true
require_bin false
require_bin pwd
require_bin head
require_bin tail
require_bin sort
require_bin uniq
require_bin tee
require_bin tr
require_bin cut
require_bin paste
require_bin nl
require_bin od
require_bin expr
require_bin date
require_bin sleep
require_bin ln
require_bin readlink
require_bin realpath
require_bin basename
require_bin dirname
require_bin touch
require_bin chmod
require_bin chown
require_bin mv
require_bin printf
require_bin yes
require_bin seq
require_bin uname
require_bin stat
require_bin df
require_bin ls
require_bin test
require_bin [
require_bin grep
require_bin kill
require_bin id
require_bin which
require_bin xargs
require_bin whoami
require_bin du
require_bin clear
require_bin hostname
require_bin nproc
require_bin env
require_bin sed
require_bin awk
require_bin find
require_bin sh

require_bin uptime
require_bin free
require_bin mount
require_bin strings
require_bin rev
require_bin column
require_bin col
require_bin more
require_bin watch
require_bin hexdump
require_bin sha256
require_bin hkdf
require_bin aes128
require_bin gcm128
require_bin x25519
require_bin tlsrec
require_bin tls13kdf

exit 0
