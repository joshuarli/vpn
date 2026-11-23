exec 2>&1
set +e
W=/tmp/matrix
rm -rf $W; mkdir -p $W
mount -o remount,rw /proc/sys 2>/dev/null
mkdir -p /dev/net; [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200

echo "cell client=$CLIENT_BIN server=$SERVER_BIN keyed=$KEYED"
KEYARGS=""
MODE_LINE="Running in authentication-only mode (no encryption)"
if [ "$KEYED" = 1 ]; then
  MODE_LINE="Running in encrypted mode with authentication"
  head -c 32 /dev/urandom > $W/vpn.key
  KEYARGS="-k $W/vpn.key"
fi
CP=""; SP=""; PP=""
DAEMONS=""
COMMON_REF=0
[ "$CLIENT_BIN" = "$ORACLE_BIN" ] && [ "$SERVER_BIN" = "$ORACLE_BIN" ] && COMMON_REF=1

pass() { echo "@@ $1|PASS|$2"; }
flunk() { echo "@@ $1|FAIL|$2"; }
squash() { printf '%s' "$*" | tr '\n\t' '  ' | cut -c1-500; }
check() {
  local id=$1 detail=$2 out
  shift 2
  if out=$("$@" 2>&1); then pass "$id" "$detail"; else flunk "$id" "$detail: $(squash "$out")"; fi
}
waitfor() {
  local t=$1 i=0
  shift
  until "$@" >/dev/null 2>&1; do
    i=$((i+1))
    [ $i -ge $((t*5)) ] && return 1
    sleep 0.2
  done
  return 0
}

cat > $W/chk.py <<'PY'
import json, sys
path, rc, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3]
try:
    d = json.load(open(path))
except Exception as e:
    print("no iperf3 json (rc=%d): %s" % (rc, e)); sys.exit(1)
if rc != 0 or "error" in d:
    print("iperf3 rc=%d error=%s" % (rc, d.get("error"))); sys.exit(1)
e = d["end"]
keys = ["sum_sent", "sum_received"]
if mode == "bidir":
    keys += ["sum_sent_bidir_reverse", "sum_received_bidir_reverse"]
parts = []
for k in keys:
    s = e.get(k)
    if not s or s.get("bytes", 0) <= 0:
        print("%s moved no bytes" % k); sys.exit(1)
    parts.append("%s=%.0fMbit/s" % (k[4:], s["bytes"] * 8 / max(s["seconds"], 1e-9) / 1e6))
print(" ".join(parts))
PY

ip netns add c; ip netns add s; ip netns add l
ip link add vc netns c type veth peer name vs netns s
ip link add vh netns l type veth peer name vl netns s
ip -n c addr add 10.77.0.1/24 dev vc; ip -n s addr add 10.77.0.2/24 dev vs
ip -n s addr add 10.88.0.1/24 dev vl; ip -n l addr add 10.88.0.2/24 dev vh
for n in c s l; do ip -n $n link set lo up; done
ip -n c link set vc up; ip -n s link set vs up; ip -n s link set vl up; ip -n l link set vh up
ip -n c route add default via 10.77.0.2
ip -n s route add default via 10.88.0.2 dev vl
ip netns exec s sysctl -qw net.ipv4.ip_forward=0

for spec in "s iptables -t raw PREROUTING" "s iptables -t nat POSTROUTING" "s iptables -t filter FORWARD" "s iptables -t filter INPUT" \
            "c iptables -t raw PREROUTING"; do
  set -- $spec
  ip netns exec $1 $2 $3 $4 -I $5 -j ACCEPT
  ip netns exec $1 $2 $3 $4 -D $5 -j ACCEPT
done

ll_up() {
  ip -n c -6 route | grep -q 'fe80::/64 dev vc' && ip -n s -6 route | grep -q 'fe80::/64 dev vs' \
    && ip -n s -6 route | grep -q 'fe80::/64 dev vl' && ip -n l -6 route | grep -q 'fe80::/64 dev vh'
}
waitfor 20 ll_up

snap() {
  local n
  for n in c s; do
    {
      echo "# iptables"; ip netns exec $n iptables-save | sed -e '/^#/d' -e 's/ \[[0-9]*:[0-9]*\]$//'
      echo "# ip6tables"; ip netns exec $n ip6tables-save | sed -e '/^#/d' -e 's/ \[[0-9]*:[0-9]*\]$//'
      echo "# nft"; ip netns exec $n nft list ruleset | sed 's/counter packets [0-9]* bytes [0-9]*/counter/'
      echo "# rule"; ip -n $n rule
      echo "# rule6"; ip -n $n -6 rule
      echo "# route"; ip -n $n route show table all | grep -v '^local fe80::'
      echo "# route6"; ip -n $n -6 route show table all | grep -v '^local fe80::'
      echo "# links"; ip -n $n -o link show | awk '{print $2}'
    } > $W/$1.$n 2>&1
  done
}
refsnap() {
  local n
  for n in c s; do
    {
      ip netns exec $n iptables-save | sed -e '/^#/d' -e 's/ \[[0-9]*:[0-9]*\]$//'
      ip netns exec $n nft list ruleset | sed 's/counter packets [0-9]* bytes [0-9]*/counter/'
      echo "# rule"; ip -n $n rule
      echo "# rule6"; ip -n $n -6 rule
      echo "# route"; ip -n $n route show table all | grep -v 'fe80::'
      echo "# route6"; ip -n $n -6 route show table all | grep -v 'fe80::'
      echo "# addr"; ip -n $n -o -4 addr show dev tun0 | awk '{print $2,$3,$4,$5,$6,$7}'
      echo "# mtu"; ip -n $n -o link show tun0 | sed -n 's/.*mtu \([0-9]*\).*/\1/p'
      echo "# forward"; ip netns exec $n sysctl -n net.ipv4.ip_forward
    } > $W/$1.ref.$n 2>&1
  done
}

cli_sock() { ip netns exec c ss -Hun | grep -q '10.77.0.2:41194'; }
cli_port() { ip netns exec c ss -Hun | awk '{for (i=2;i<=NF;i++) if ($i == "10.77.0.2:41194") {n=split($(i-1),a,":"); print a[n]; exit}}'; }
srv_up() { ip netns exec s iptables-save -t filter | grep -q -- '-i tun0 -o vl -j ACCEPT'; }
cli_up() { ip -n c -6 rule | grep -q suppress_prefixlength; }
mtu_of() { ip -n $1 -o link show tun0 | sed -n 's/.*mtu \([0-9]*\).*/\1/p'; }

start_server() { # log bin
  ip netns exec s $2 $KEYARGS server auto > $W/$1 2>&1 &
  SP=$!
}
start_client() { # log bin [options]
  local log=$1 bin=$2
  shift 2
  ip netns exec c $bin "$@" $KEYARGS client 10.77.0.2 auto auto auto auto 10.77.0.2 > $W/$log 2>&1 &
  CP=$!
}
stop_pair() {
  CRC=127; SRC=127
  if [ -n "$CP" ]; then kill -TERM $CP 2>/dev/null; wait $CP; CRC=$?; fi
  if [ -n "$SP" ]; then kill -TERM $SP 2>/dev/null; wait $SP; SRC=$?; fi
  CP=""; SP=""
}
stop_all() {
  [ -n "$PP" ] && kill $PP 2>/dev/null
  PP=""
  stop_pair
}

tping() { # id ns src dst
  local out
  out=$(ip netns exec $2 ping -c 3 -W 2 ${3:+-I $3} $4 2>&1)
  if echo "$out" | grep -q ' 0% packet loss'; then pass $1 "3/3 replies $2 -> $4"; else flunk $1 "$(squash "$out")"; fi
}
tcp() { # id ns target mode
  local id=$1 flag="" rc res
  case $4 in rev) flag=-R;; bidir) flag=--bidir;; esac
  ip netns exec $2 iperf3 -c $3 -t 2 -J $flag > $W/$id.json 2> $W/$id.err
  rc=$?
  res=$(python3 $W/chk.py $W/$id.json $rc $4 2>&1)
  if [ $? -eq 0 ]; then pass $id "$res"; else flunk $id "$res $(squash "$(cat $W/$id.err)")"; fi
}
same() { # id label file_a file_b
  if diff $3 $4 > $W/diff.$1 2>&1; then pass $1 "$2"; else flunk $1 "$2 differ: $(squash "$(head -c 600 $W/diff.$1)")"; fi
}
exited() { # id who rc log
  if [ "$3" = 0 ] && grep -qx 'Done.' $4; then pass $1 "$2 exited 0 and printed Done."
  else flunk $1 "$2 exit=$3 done=$(grep -cx 'Done.' $4)"; fi
}
quiet_log() { # id who log
  if grep -v 'Unable to run \[ip rule delete table 42069\]' $3 | grep -q 'Unable to run'; then
    flunk $1 "$2 failed to run a command: $(grep 'Unable to run' $3 | head -3 | tr '\n' ' ')"
  else pass $1 "$2 ran every routing command"; fi
}
has() { grep -q -- "$1" "$2"; }

for ns in s c l; do
  case $ns in s) pf=ips;; c) pf=ipc;; l) pf=ipl;; esac
  ip netns exec $ns iperf3 -s -D -I $W/$pf.pid --logfile $W/$pf.log
done
sleep 0.5
snap before

phase_main() {
  trap stop_all EXIT
  start_server s.log $SERVER_BIN
  if ! waitfor 20 srv_up || ! kill -0 $SP 2>/dev/null; then flunk setup.server "server rules did not appear or server died"; return; fi
  pass setup.server "server rules installed"
  start_client c.log $CLIENT_BIN
  if ! waitfor 20 cli_up || ! kill -0 $CP 2>/dev/null; then flunk setup.client "client rules did not appear or client died"; return; fi
  check setup.client "client rules installed and its UDP socket connected to the server" waitfor 10 cli_sock

  tping tunnel.ping-c2s c 192.168.192.1 192.168.192.254
  tping tunnel.ping-s2c s 192.168.192.254 192.168.192.1
  tcp tunnel.tcp-forward c 192.168.192.254 fwd
  tcp tunnel.tcp-reverse c 192.168.192.254 rev
  tcp tunnel.tcp-duplex c 192.168.192.254 bidir
  tcp tunnel.tcp-server-initiated s 192.168.192.1 fwd

  sleep 1
  snap during
  refsnap during
  for n in c s; do
    if cmp -s $W/before.$n $W/during.$n; then flunk routing.changed-$n "no routing or firewall change in $n while running"
    else pass routing.changed-$n "state in $n differs from before while running"; fi
  done
  local c4 c6
  c4=$(ip -n c rule); c6=$(ip -n c -6 rule)
  rules_ok() {
    echo "$c4" | grep -q 'from all lookup main suppress_prefixlength 0' &&
    echo "$c6" | grep -q 'from all lookup main suppress_prefixlength 0' &&
    echo "$c4" | grep -Eq 'not from all fwmark 0x[0-9a-f]+ lookup 42069' &&
    echo "$c6" | grep -Eq 'not from all fwmark 0x[0-9a-f]+ lookup 42069' &&
    echo "$c4" | awk '/suppress_prefixlength/{s=NR} /lookup 42069/{t=NR} END{exit !(s && t && s<t)}' &&
    ip -n c route show table 42069 | grep -q '^default dev tun0' &&
    ip -n c -6 route show table 42069 | grep -q '^default dev tun0' &&
    has '-A PREROUTING -d 192.168.192.1/32 ! -i tun0 -m addrtype ! --src-type LOCAL -j DROP' $W/during.c
  }
  check routing.client-rules "rule/table 42069 defaults via tun0 in v4+v6, suppress_prefixlength before it, raw DROP" rules_ok
  paths_ok() {
    ip -n c route get 10.88.0.2 | grep -q 'dev tun0' &&
    ip -n c route get 192.168.192.254 | grep -q 'dev tun0' &&
    ip -n c route get 10.77.0.2 | grep -q 'dev vc' &&
    ! ip -n c route get 10.77.0.2 | grep -q 'dev tun0'
  }
  check routing.client-paths "LAN and tunnel peer resolve via tun0, the server itself stays on vc" paths_ok
  server_rules_ok() {
    [ "$(ip netns exec s sysctl -n net.ipv4.ip_forward)" = 1 ] &&
    has '-A POSTROUTING -s 192.168.192.1/32 -o vl -j MASQUERADE' $W/during.s &&
    has '-A FORWARD -i tun0 -o vl -j ACCEPT' $W/during.s &&
    has '-A FORWARD -i vl -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT' $W/during.s &&
    has '-A PREROUTING -d 192.168.192.254/32 ! -i tun0 -m addrtype ! --src-type LOCAL -j DROP' $W/during.s
  }
  check routing.server-rules "ip_forward=1, MASQUERADE, both FORWARD rules and raw DROP on external vl" server_rules_ok
  addr_ok() {
    ip -n c -o -4 addr show dev tun0 | grep -q '192.168.192.1 peer 192.168.192.254/32' &&
    ip -n s -o -4 addr show dev tun0 | grep -q '192.168.192.254 peer 192.168.192.1/32' &&
    ip -n c -o -6 addr show dev tun0 | grep -q '64:ff9b::c0a8:c001 peer 64:ff9b::c0a8:c0fe' &&
    ip -n s -o -6 addr show dev tun0 | grep -q '64:ff9b::c0a8:c0fe peer 64:ff9b::c0a8:c001'
  }
  check routing.addresses "tun0 v4 and v6 point-to-point addresses on both ends" addr_ok
  mtu_ok() { [ "$(mtu_of c)" = 1404 ] && [ "$(mtu_of s)" = 1404 ]; }
  check routing.mtu "tun0 mtu 1404 on both ends" mtu_ok

  tping routed.ping c "" 10.88.0.2
  tcp routed.tcp-forward c 10.88.0.2 fwd
  tcp routed.tcp-reverse c 10.88.0.2 rev
  tcp routed.tcp-duplex c 10.88.0.2 bidir
  nat_ok() {
    has 'Accepted connection from 10.88.0.1,' $W/ipl.log && ! has 'Accepted connection from 192.168.192' $W/ipl.log
  }
  check routed.nat-source "LAN host saw the server's 10.88.0.1, never 192.168.192.1" nat_ok

  ip netns exec s iptables -I INPUT -i vs -p udp --dport 41194 -j DROP
  out=$(ip netns exec c ping -c 3 -W 1 -I 192.168.192.1 192.168.192.254 2>&1)
  if echo "$out" | grep -q ' 100% packet loss'; then pass reconnect.blackhole-drops "100% loss while the server input is dropped"
  else flunk reconnect.blackhole-drops "$(squash "$out")"; fi
  ip netns exec s iptables -D INPUT -i vs -p udp --dport 41194 -j DROP
  cping() { ip netns exec c ping -c 1 -W 1 -I 192.168.192.1 192.168.192.254; }
  check reconnect.blackhole-recovers "traffic resumed after the drop rule was removed" waitfor 20 cping

  local p0 p1
  p0=$(cli_port)
  ip netns exec c ping -i 0.2 -I 192.168.192.1 192.168.192.254 > /dev/null 2>&1 &
  PP=$!
  kill -TERM $SP; wait $SP; SRC=$?; SP=""
  exited reconnect.server-stop "server" $SRC $W/s.log
  snap mid
  same reconnect.server-rules-removed "server state matches the pre-run state right after its stop" $W/before.s $W/mid.s
  sleep 4
  check reconnect.client-alive "client survived the outage" kill -0 $CP
  start_server s2.log $SERVER_BIN
  check reconnect.server-restart "server came back with its rules" waitfor 20 srv_up
  kill $PP 2>/dev/null; PP=""
  check reconnect.ping-resumes "ping through the tunnel works after the reconnect" waitfor 40 cping
  p1=$(cli_port)
  tcp reconnect.tcp-forward c 192.168.192.254 fwd
  tcp reconnect.tcp-reverse c 192.168.192.254 rev
  tping reconnect.ping-s2c s 192.168.192.254 192.168.192.1
  tping reconnect.routed c "" 10.88.0.2

  stop_pair
  local tries
  tries=$(grep -c '^Trying to reconnect' $W/c.log)
  if [ "$tries" -gt 0 ] && [ -n "$p0" ] && [ -n "$p1" ] && [ "$p0" != "$p1" ]; then
    pass reconnect.client-retries "client logged $tries reconnect attempts and replaced its UDP socket (port $p0 -> $p1)"
  else flunk reconnect.client-retries "reconnect attempts logged: $tries; client UDP port before '$p0', after '$p1'"; fi
  mode_ok() { has "^$MODE_LINE" $W/c.log && has "^$MODE_LINE" $W/s.log && has "^$MODE_LINE" $W/s2.log; }
  check setup.mode "every process logged: $MODE_LINE" mode_ok
  check reconnect.server-sees-client "restarted server logged the client" has '^Client connected from \[10.77.0.1\]' $W/s2.log
  check setup.handshake "client logged Connected and the first server logged the client" \
    sh -c "grep -q '^Connected' $W/c.log && grep -q '^Client connected from \[10.77.0.1\]' $W/s.log"
  exited teardown.client-exit "client" $CRC $W/c.log
  exited teardown.server-exit "server" $SRC $W/s2.log
  quiet_log teardown.client-commands client $W/c.log
  quiet_log teardown.server-commands server $W/s2.log
  snap after
  same teardown.state-client "client iptables-save, nft ruleset, ip rule, ip route v4+v6 match the pre-run state" $W/before.c $W/after.c
  same teardown.state-server "server iptables-save, nft ruleset, ip rule, ip route v4+v6 match the pre-run state" $W/before.s $W/after.s
}
mtu_run() { # label client_bin server_bin
  local l=$1
  start_server $l.s.log $3
  waitfor 20 srv_up || { echo "server did not install its rules"; return 1; }
  start_client $l.c.log $2 -d
  mtu_changed() { [ -n "$(mtu_of c)" ] && [ "$(mtu_of c)" != 1404 ]; }
  waitfor 120 mtu_changed || { echo "client tun0 mtu never left 1404"; return 1; }
  sleep 0.5
  return 0
}
applied_mtu() { sed -n 's/^Setting TUN MTU to discovered value: [0-9]* bytes (effective: \([0-9]*\) bytes.*/\1/p' $W/$1.c.log; }

phase_mtu() {
  trap stop_all EXIT
  ip netns exec s iptables -t raw -A PREROUTING -i vs -p udp -m length --length 1301:65535 -j DROP
  local REF=""
  if [ $COMMON_REF = 0 ]; then
    mtu_run ref $ORACLE_BIN $ORACLE_BIN > $W/ref.out 2>&1 || { flunk mtu.reference "$(squash "$(cat $W/ref.out)")"; return; }
    REF=$(mtu_of c)
    stop_pair
    if [ "$CRC" != 0 ] || [ "$SRC" != 0 ] || ! has '^MTU discovery complete' $W/ref.c.log; then flunk mtu.reference "reference pair exited $CRC/$SRC or discovery incomplete"; return; fi
    pass mtu.reference "C/C discovery chose tun0 mtu $REF"
  fi
  mtu_run cell $CLIENT_BIN $SERVER_BIN > $W/cell.out 2>&1 || { flunk mtu.discovery "$(squash "$(cat $W/cell.out)")"; return; }
  local got eff
  got=$(mtu_of c)
  [ -z "$REF" ] && REF=$got
  if [ "$got" = "$REF" ]; then pass mtu.matches-reference "client tun0 mtu $got equals the C/C reference $REF"
  else flunk mtu.matches-reference "client tun0 mtu '$got', C/C reference '$REF'"; fi
  if [ "$(mtu_of s)" = 1404 ]; then pass mtu.server-unchanged "server tun0 mtu stays 1404"
  else flunk mtu.server-unchanged "server tun0 mtu is '$(mtu_of s)'"; fi
  tping mtu.ping c 192.168.192.1 192.168.192.254
  tcp mtu.tcp c 192.168.192.254 bidir
  stop_pair
  check mtu.discovery "client logged MTU discovery complete" has '^MTU discovery complete' $W/cell.c.log
  eff=$(applied_mtu cell)
  if [ "$got" = "$eff" ]; then pass mtu.applied "client tun0 mtu $got equals the discovered effective value"
  else flunk mtu.applied "client tun0 mtu '$got', discovery logged effective '$eff'"; fi
  exited mtu.client-exit "client" $CRC $W/cell.c.log
  exited mtu.server-exit "server" $SRC $W/cell.s.log
  ip netns exec s iptables -t raw -D PREROUTING -i vs -p udp -m length --length 1301:65535 -j DROP
  snap after-mtu
  same mtu.teardown-client "client state matches the pre-run state after discovery runs" $W/before.c $W/after-mtu.c
  same mtu.teardown-server "server state matches the pre-run state after discovery runs" $W/before.s $W/after-mtu.s
}

( phase_main )
( phase_mtu )

for n in c s; do
  echo "@@BEGIN during.$n"; cat $W/during.ref.$n 2>/dev/null; echo "@@END"
done
for f in $W/*.log; do case $f in */ip?.log) continue;; esac; echo "--- $f"; cat $f; done
exit 0
