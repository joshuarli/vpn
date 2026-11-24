use super::common;
use crate::container;
use crate::util::Result;

const USAGE: &str = "usage: cargo xtask lab smoke [--discover-mtu] [--rust-target <triple>]

--discover-mtu starts the client with -d and checks that its TUN MTU follows the discovered value.
--rust-target runs the release binary built for that triple (aarch64-unknown-linux-musl) instead of the debug build.";

const SCRIPT: &str = r##"
W=/tmp/smoke
rm -rf $W; mkdir -p $W
mount -o remount,rw /proc/sys 2>/dev/null || true
mkdir -p /dev/net; [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
CB=@CLIENT_BIN@
SB=@SERVER_BIN@
CARGS=""
head -c 32 /dev/urandom > $W/vpn.key; KEY="-k $W/vpn.key"
@DISCOVER_SETUP@
CP=""; SP=""; IP=""

fail() {
  echo "SMOKE FAIL: $*" >&2
  for f in $W/*.log $W/during.c $W/during.s; do [ -f "$f" ] && { echo "--- $f" >&2; cat "$f" >&2; }; done
  exit 1
}
cleanup() {
  for p in $CP $SP $IP; do kill -KILL $p 2>/dev/null || true; done
}
trap cleanup EXIT

waitfor() {
  d=$1; t=$2; shift 2; i=0
  while ! "$@" >/dev/null 2>&1; do
    i=$((i+1)); [ $i -ge $((t*5)) ] && fail "timeout waiting for $d"
    sleep 0.2
  done
}

ip netns add c; ip netns add s
ip link add vc netns c type veth peer name vs netns s
ip -n c addr add 10.77.0.1/24 dev vc; ip -n s addr add 10.77.0.2/24 dev vs
for n in c s; do ip -n $n link set lo up; done
ip -n c link set vc up; ip -n s link set vs up
ip -n c route add default via 10.77.0.2; ip -n s route add default via 10.77.0.1

snap() {
  for n in c s; do
    {
      echo "# iptables"; ip netns exec $n iptables-save | grep '^-A' || true
      echo "# rule"; ip -n $n rule
      echo "# rule6"; ip -n $n -6 rule
      echo "# route"; ip -n $n route show table all | grep -v "^local fe80::"
      echo "# route6"; ip -n $n -6 route show table all | grep -v "^local fe80::"
      echo "# links"; ip -n $n -o link show | awk '{print $2}'
    } > $W/$1.$n
  done
}

srv_up() { ip netns exec s iptables-save -t filter | grep -q -- '-i tun0 -o vs -j ACCEPT'; }
cli_up() { ip -n c -6 rule | grep -q suppress_prefixlength; }
mtu_of() { ip -n $1 -o link show tun0 | sed -n 's/.*mtu \([0-9]*\).*/\1/p'; }

ping_ok() {
  out=$(ip netns exec $1 ping -c 3 -W 2 -I $2 $3 2>&1) || { echo "$out"; fail "ping $1 to $3"; }
  echo "$out" | grep -q ' 0% packet loss' || { echo "$out"; fail "ping loss $1 to $3"; }
  echo "ping $1 -> $3: 3/3"
}

ll_up() { ip -n c -6 route | grep -q 'fe80::/64 dev vc' && ip -n s -6 route | grep -q 'fe80::/64 dev vs'; }
waitfor "IPv6 link-local routes" 20 ll_up

snap before

ip netns exec s $SB $KEY server auto > $W/s.log 2>&1 &
SP=$!
waitfor "server rules" 20 srv_up
ip netns exec c $CB $CARGS $KEY client 10.77.0.2 auto auto auto auto 10.77.0.2 > $W/c.log 2>&1 &
CP=$!
waitfor "client rules" 20 cli_up

ping_ok c 192.168.192.1 192.168.192.254
ping_ok s 192.168.192.254 192.168.192.1

ip netns exec s iperf3 -s -D -I $W/iperf.pid --logfile $W/iperf.log
IP=$(cat $W/iperf.pid)
sleep 0.5
for mode in "" "-R"; do
  out=$(ip netns exec c iperf3 -c 192.168.192.254 -t 2 $mode 2>&1) || { echo "$out"; fail "iperf3 $mode"; }
  echo "$out" | grep -q receiver || { echo "$out"; fail "iperf3 $mode printed no receiver line"; }
  rate=$(echo "$out" | awk '/receiver/{print $(NF-2), $(NF-1)}')
  echo "tcp ${mode:-c->s}: $rate"
  case "$rate" in 0*) fail "iperf3 $mode moved no data";; esac
done
kill $IP; IP=""

@MTU_CHECK@

snap during
for n in c s; do
  cmp -s $W/before.$n $W/during.$n && fail "no routing or firewall change in $n while running"
done
grep -q 42069 $W/during.c || fail "client has no table 42069 rule"
grep -q 'default dev tun0 table 42069' $W/during.c || fail "client has no default route in table 42069"
grep -q -- '-A PREROUTING -d 192.168.192.1/32 ! -i tun0 -m addrtype ! --src-type LOCAL -j DROP' $W/during.c || fail "client raw DROP rule missing"
grep -q -- '-A POSTROUTING -s 192.168.192.1/32 -o vs -j MASQUERADE' $W/during.s || fail "server MASQUERADE rule missing"
grep -q -- '-A FORWARD -i tun0 -o vs -j ACCEPT' $W/during.s || fail "server FORWARD out rule missing"
grep -q -- '-A FORWARD -i vs -o tun0' $W/during.s || fail "server FORWARD return rule missing"
grep -q -- '-A PREROUTING -d 192.168.192.254/32 ! -i tun0 -m addrtype ! --src-type LOCAL -j DROP' $W/during.s || fail "server raw DROP rule missing"
echo "rules present while running: ok"

kill -TERM $CP; rc=0; wait $CP || rc=$?; CP=""
[ $rc = 0 ] || fail "client exited $rc after SIGTERM"
kill -TERM $SP; rc=0; wait $SP || rc=$?; SP=""
[ $rc = 0 ] || fail "server exited $rc after SIGTERM"
for l in c s; do
  grep -qx 'Done.' $W/$l.log || fail "$l did not print Done."
  grep -v 'Unable to run \[ip rule delete table 42069\]' $W/$l.log | grep -q 'Unable to run' && fail "$l failed to run a command"
done
grep -q '^Connected' $W/c.log || fail "client never printed Connected"
grep -q '^Client connected from \[10.77.0.1\]' $W/s.log || fail "server never saw the client"
echo "exit: client 0, server 0, both printed Done."
@POST_CHECK@

snap after
for n in c s; do
  diff $W/before.$n $W/after.$n > $W/teardown.$n.diff || { cat $W/teardown.$n.diff; fail "rules left behind in $n"; }
done
echo "teardown: routing and firewall state identical to before in both namespaces"
echo "smoke: PASS client=@CLIENT_NAME@ server=@SERVER_NAME@"
"##;

const MTU_CHECK_FIXED: &str = r##"
for n in c s; do
  m=$(mtu_of $n)
  [ "$m" = 1404 ] || fail "tun0 mtu in $n is '$m', expected 1404"
done
echo "tun0 mtu: 1404 both sides"
"##;

const MTU_CHECK_DISCOVER: &str = r##"
CMTU=$(mtu_of c)
[ "$(mtu_of s)" = 1404 ] || fail "server tun0 mtu changed"
echo "tun0 mtu: client $CMTU (discovery), server 1404"
"##;

const POST_CHECK_DISCOVER: &str = r##"
want=$(sed -n 's/^Setting TUN MTU to discovered value: [0-9]* bytes (effective: \([0-9]*\) bytes.*/\1/p' $W/c.log)
[ -n "$want" ] || fail "client never reported a discovered MTU"
grep -q '^MTU discovery complete' $W/c.log || fail "client did not finish MTU discovery"
[ "$CMTU" = "$want" ] || fail "client tun0 mtu was '$CMTU', discovery chose '$want'"
echo "discovered MTU applied: $want"
"##;

pub fn run(args: &[String]) -> Result<()> {
    let mut discover = false;
    let mut rust_target: Option<String> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--discover-mtu" => discover = true,
            "--rust-target" => {
                rust_target = Some(it.next().ok_or_else(|| format!("--rust-target needs a triple\n\n{USAGE}"))?.clone());
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            other => return Err(format!("unexpected argument `{other}`\n\n{USAGE}")),
        }
    }
    let bin = common::prepare(rust_target.as_deref())?;
    let discover_setup = if discover { "CARGS=-d" } else { ":" };
    let mtu_check = if discover { MTU_CHECK_DISCOVER } else { MTU_CHECK_FIXED };
    let post_check = if discover { POST_CHECK_DISCOVER } else { ":" };
    let script = SCRIPT
        .replace("@CLIENT_BIN@", &bin)
        .replace("@SERVER_BIN@", &bin)
        .replace("@DISCOVER_SETUP@", discover_setup)
        .replace("@MTU_CHECK@", mtu_check)
        .replace("@POST_CHECK@", post_check)
        .replace("@CLIENT_NAME@", "rust")
        .replace("@SERVER_NAME@", "rust");
    container::Run::new(&script).status()
}
