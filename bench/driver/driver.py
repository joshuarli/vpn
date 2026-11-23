#!/usr/bin/env python3
import argparse
import json
import os
import re
import resource
import subprocess
import sys
import time

TICK = os.sysconf("SC_CLK_TCK")
RUN_DIR = "/tmp/bench-run"
CLIENT_TUN = "192.168.192.1"
SERVER_TUN = "192.168.192.254"
CLIENT_UNDERLAY = "10.77.0.1"
SERVER_UNDERLAY = "10.77.0.2"
KEY_PATH = RUN_DIR + "/key"


class Invalid(Exception):
    pass


class Out:
    def __init__(self, path):
        self.f = open(path, "a", buffering=1)

    def sample(self, ctx, unit, metric, value, unit_label, higher, kind, gate=True, valid=True,
               reason=None, extra=None, env=None):
        rec = {
            "layer": ctx["layer"],
            "unit": unit,
            "metric": metric,
            "value": value,
            "unit_label": unit_label,
            "higher_is_better": higher,
            "kind": kind,
            "gate": gate,
            "arm": ctx["arm"],
            "pair": ctx["pair"],
            "position": ctx["position"],
            "valid": valid,
            "invalid_reason": reason,
            "extra": extra or {},
            "env": env or {},
            "t": time.time(),
        }
        self.f.write(json.dumps(rec) + "\n")


def sh(script, check=True):
    r = subprocess.run(["sh", "-euc", script], capture_output=True, text=True)
    if check and r.returncode != 0:
        raise Invalid("script failed: %s: %s" % (script[:200], r.stderr.strip()[-300:]))
    return r


def pick_cores():
    avail = sorted(os.sched_getaffinity(0))
    pool = avail[2:] if len(avail) >= 9 else avail
    names = ["client", "server", "gen_client", "gen_server", "probe", "echo", "micro"]
    return {n: pool[i % len(pool)] for i, n in enumerate(names)}


def arm_order(pair):
    return ["baseline", "candidate"] if pair % 2 == 0 else ["candidate", "baseline"]


def cpu_ticks(pid):
    with open("/proc/%d/stat" % pid) as f:
        s = f.read()
    fields = s[s.rindex(")") + 2:].split()
    return int(fields[11]) + int(fields[12])


def proc_alive(p):
    return p.poll() is None


def read_kv(path, keys):
    out = {}
    with open(path) as f:
        for line in f:
            k, _, v = line.partition(":")
            if k in keys:
                out[k] = int(v.split()[0])
    return out


def proc_mem(pid):
    st = read_kv("/proc/%d/status" % pid, {"VmSize", "VmRSS", "VmHWM", "RssAnon", "RssFile"})
    sm = read_kv("/proc/%d/smaps_rollup" % pid, {"Rss", "Pss", "Pss_Anon", "Pss_File", "Private_Dirty"})
    return {"vmsize_kb": st["VmSize"], "rss_kb": st["VmRSS"], "hwm_kb": st["VmHWM"],
            "rss_anon_kb": st["RssAnon"], "rss_file_kb": st["RssFile"], "pss_kb": sm["Pss"],
            "pss_anon_kb": sm["Pss_Anon"], "private_dirty_kb": sm["Private_Dirty"]}


def granted_buffers(ns, pid):
    r = sh("ip netns exec %s ss -u -a -m -n -p" % ns, check=False)
    lines = r.stdout.splitlines()
    for i, line in enumerate(lines):
        if "pid=%d," % pid in line and i + 1 < len(lines):
            m = re.search(r"rb(\d+),t(\d+),tb(\d+)", lines[i + 1])
            if m:
                return {"rcvbuf": int(m.group(1)), "sndbuf": int(m.group(3))}
    return {"rcvbuf": None, "sndbuf": None}


def tun_rx_packets(ns):
    r = sh("ip netns exec %s ip -s -j link show tun0" % ns, check=False)
    try:
        return json.loads(r.stdout)[0]["stats64"]["rx"]["packets"]
    except (ValueError, KeyError, IndexError):
        return 0


def link_features(ns, dev):
    r = sh("ip -n %s -d -j link show %s" % (ns, dev), check=False)
    try:
        d = json.loads(r.stdout)[0]
        keep = {k: d.get(k) for k in ("mtu", "qdisc", "txqlen", "gso_max_size", "gso_max_segs",
                                       "tso_max_size", "tso_max_segs", "gro_max_size", "num_tx_queues")}
        return keep
    except (ValueError, IndexError):
        return {}


class Session:
    def __init__(self, plan, arm, mtu, tun_mtu=None, imp=None):
        self.plan = plan
        self.arm = arm
        self.bin = plan["arms"][arm]["twice"]
        self.cores = plan["cores"]
        self.mtu = mtu
        self.tun_mtu = tun_mtu
        self.procs = {}
        self.extra_procs = []
        self.up = False

    def ns_cmd(self, ns, cpu, argv):
        cmd = ["ip", "netns", "exec", ns]
        if cpu is not None:
            cmd += ["taskset", "-c", str(cpu)]
        return cmd + [str(a) for a in argv]

    def spawn(self, ns, cpu, argv, name, capture=False):
        os.makedirs(RUN_DIR, exist_ok=True)
        if capture:
            p = subprocess.Popen(self.ns_cmd(ns, cpu, argv), stdout=subprocess.PIPE,
                                 stderr=open("%s/%s.err" % (RUN_DIR, name), "w"), text=True)
        else:
            log = open("%s/%s.log" % (RUN_DIR, name), "w")
            p = subprocess.Popen(self.ns_cmd(ns, cpu, argv), stdout=log, stderr=subprocess.STDOUT)
        self.extra_procs.append(p)
        return p

    def setup(self):
        os.makedirs(RUN_DIR, exist_ok=True)
        with open(KEY_PATH, "wb") as f:
            f.write(bytes((self.plan["seed"] * 31 + i * 7) & 0xFF for i in range(32)))
        sh(self.plan["topology"]["setup"][str(self.mtu)])

    def netem(self, name):
        sh(self.plan["topology"]["clear_netem"])
        if name:
            sh(self.plan["topology"]["netem"][name])

    def start_tunnel(self):
        if not os.path.exists(self.bin):
            err = self.plan["arms"][self.arm].get("twice_build_error")
            raise Invalid("endpoint binary missing: %s (%s)" % (self.bin, err))
        extra = ["-m", str(self.tun_mtu)] if self.tun_mtu else []
        key = ["-k", KEY_PATH]
        srv = self.spawn("s", self.cores["server"], [self.bin] + key + extra + ["server", "auto"], "twice-server")
        time.sleep(0.5)
        cli = self.spawn("c", self.cores["client"],
                         [self.bin] + key + extra + ["client", SERVER_UNDERLAY, "auto", "auto", "auto", "auto", SERVER_UNDERLAY],
                         "twice-client")
        self.procs = {"server": srv, "client": cli}
        deadline = time.time() + 8
        while time.time() < deadline:
            self.check_alive()
            r = subprocess.run(self.ns_cmd("c", None, ["ping", "-c", "1", "-W", "1", "-I", CLIENT_TUN, SERVER_TUN]),
                               capture_output=True)
            if r.returncode == 0:
                self.up = True
                return
            time.sleep(0.2)
        raise Invalid("tunnel did not come up within 8 s")

    def check_alive(self):
        for role, p in self.procs.items():
            rc = p.poll()
            if rc is not None:
                tail = ""
                try:
                    tail = open("%s/twice-%s.log" % (RUN_DIR, role)).read()[-200:].strip().replace("\n", " | ")
                except OSError:
                    pass
                raise Invalid("endpoint nonzero exit: %s rc=%d %s" % (role, rc, tail))

    def stop(self):
        reasons = []
        for role, p in list(self.procs.items()):
            if p.poll() is None:
                p.terminate()
        for role, p in list(self.procs.items()):
            try:
                rc = p.wait(timeout=8)
            except subprocess.TimeoutExpired:
                p.kill()
                rc = p.wait()
                reasons.append("%s did not exit on SIGTERM" % role)
            if rc not in self.plan["clean_exit_codes"]:
                reasons.append("endpoint nonzero exit: %s rc=%d" % (role, rc))
        for p in self.extra_procs:
            if p.poll() is None:
                p.kill()
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        self.extra_procs = []
        self.procs = {}
        self.up = False
        return reasons

    def teardown(self):
        sh(self.plan["topology"]["teardown"], check=False)

    def pid(self, role):
        return self.procs[role].pid

    def env(self):
        env = {"granted": {}, "link": {"vc": link_features("c", "vc"), "vs": link_features("s", "vs")},
               "offload_tool": "ethtool unavailable; ip -d link features recorded"}
        if self.procs:
            env["granted"] = {"client": granted_buffers("c", self.pid("client")),
                              "server": granted_buffers("s", self.pid("server"))}
        return env


def window(sess, fn):
    cpid, spid = (sess.pid("client"), sess.pid("server")) if sess.procs else (None, None)
    c0 = cpu_ticks(cpid) if cpid else 0
    s0 = cpu_ticks(spid) if spid else 0
    p0 = tun_rx_packets("c") + tun_rx_packets("s") if cpid else 0
    t0 = time.monotonic()
    res = fn()
    wall = time.monotonic() - t0
    c1 = cpu_ticks(cpid) if cpid else 0
    s1 = cpu_ticks(spid) if spid else 0
    p1 = tun_rx_packets("c") + tun_rx_packets("s") if cpid else 0
    return res, {"wall_s": wall, "cpu_s": (c1 - c0 + s1 - s0) / TICK, "client_cpu_s": (c1 - c0) / TICK,
                 "server_cpu_s": (s1 - s0) / TICK, "tun_packets": p1 - p0}


def wait_listen(ns, port):
    for _ in range(40):
        r = sh("ip netns exec %s ss -ltn sport = :%d" % (ns, port), check=False)
        if ":%d" % port in r.stdout:
            return
        time.sleep(0.05)
    raise Invalid("server on port %d never listened" % port)


def iperf(sess, direct, mode, secs, cores):
    dst = SERVER_UNDERLAY if direct else SERVER_TUN
    srv = sess.spawn("s", cores["gen_server"], ["iperf3", "-s", "-1", "-J", "-p", "5201"], "iperf-server", capture=True)
    wait_listen("s", 5201)
    args = ["iperf3", "-c", dst, "-t", secs, "-J", "-p", "5201", "--connect-timeout", "3000"]
    if mode == "rev":
        args.append("-R")
    elif mode == "duplex":
        args.append("--bidir")
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    cli = sess.spawn("c", cores["gen_client"], args, "iperf-client", capture=True)
    out, _ = cli.communicate(timeout=float(secs) + 15)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cli_cpu = (after.ru_utime + after.ru_stime) - (before.ru_utime + before.ru_stime)
    srv_out, _ = srv.communicate(timeout=15)
    if cli.returncode != 0:
        raise Invalid("iperf3 client failed rc=%d: %s" % (cli.returncode, out[-200:] if out else ""))
    j = json.loads(out)
    end = j["end"]
    bits = end["sum_received"]["bits_per_second"]
    nbytes = end["sum_received"]["bytes"]
    if mode == "duplex":
        bits += end["sum_received_bidir_reverse"]["bits_per_second"]
        nbytes += end["sum_received_bidir_reverse"]["bytes"]
    wall = end["sum_received"]["seconds"]
    return {"mbps": bits / 1e6, "bytes": nbytes, "retransmits": end.get("sum_sent", {}).get("retransmits"),
            "gen_cpu_frac": cli_cpu / max(wall, 1e-9), "tool": "iperf3 " + str(j["start"].get("version"))}


def udp_phase(sess, direct, size, pps, secs, cores, port=9000):
    dst = SERVER_UNDERLAY if direct else SERVER_TUN
    sink = sess.spawn("s", cores["gen_server"],
                      ["udpprobe", "sink", "--bind", dst, "--port", port, "--secs", secs + 6, "--idle-s", "0.7"],
                      "udp-sink", capture=True)
    time.sleep(0.3)
    cli = sess.spawn("c", cores["gen_client"],
                     ["udpprobe", "blast", "--dst", dst, "--port", port, "--size", size, "--pps", pps, "--secs", secs],
                     "udp-blast", capture=True)
    bout, _ = cli.communicate(timeout=secs + 15)
    sout, _ = sink.communicate(timeout=secs + 15)
    b, s = json.loads(bout), json.loads(sout)
    return {"mbps": s["received_mbps"], "pps": s["received_pps"], "offered_mbps": b["offered_mbps"],
            "offered_pps": b["offered_pps"], "received": s["received"], "lost": s["lost"],
            "duplicates": s["duplicates"], "reordered": s["reordered"], "bytes": s["bytes"],
            "loss_pct": 100.0 * s["lost"] / max(s["max_seq"] + 1, 1),
            "gen_cpu_frac": s["cpu_s"] / max(s["span_s"] + 0.7, 1e-9),
            "gen_behind_schedule": b["offered_pps"] < 0.98 * b["target_pps"],
            "tool": "udpprobe 1"}


def start_echo(sess, direct, cores):
    dst = SERVER_UNDERLAY if direct else SERVER_TUN
    sess.spawn("s", cores["echo"], ["udpprobe", "echo", "--bind", dst, "--port", "9001", "--secs", "3600"], "udp-echo")
    time.sleep(0.2)


def probe(sess, secs, cores, pps):
    p = sess.spawn("c", cores["probe"], ["udpprobe", "ping", "--dst", SERVER_TUN, "--port", "9001", "--size", "64",
                                          "--pps", pps, "--secs", secs, "--warm-s", "0.5"], "udp-ping", capture=True)
    out, _ = p.communicate(timeout=secs + 15)
    return json.loads(out)


def run_phase(sess, name, spec, params, direct, cores):
    secs = params["phase_s"]
    kind = spec["kind"]
    if kind == "tcp":
        return iperf(sess, direct, spec["mode"], secs, cores)
    if kind == "udp":
        return udp_phase(sess, direct, spec["size"], spec["pps"], secs, cores)
    raise Invalid("bad phase kind %s" % kind)


def latency_phase(sess, name, spec, params, cores):
    secs = params["phase_s"]
    bg = None
    sink = None
    if spec["load"] == "udp":
        sink = sess.spawn("s", cores["gen_server"], ["udpprobe", "sink", "--bind", SERVER_TUN, "--port", "9000",
                                                      "--secs", secs + 8, "--idle-s", "0.7"], "lat-sink", capture=True)
        time.sleep(0.2)
        bg = sess.spawn("c", cores["gen_client"], ["udpprobe", "blast", "--dst", SERVER_TUN, "--port", "9000",
                                                    "--size", spec["size"], "--pps", spec["pps"], "--secs", secs + 1.2],
                        "lat-blast", capture=True)
    else:
        sess.spawn("s", cores["gen_server"], ["iperf3", "-s", "-1", "-J", "-p", "5201"], "lat-iperf-server", capture=True)
        wait_listen("s", 5201)
        bg = sess.spawn("c", cores["gen_client"], ["iperf3", "-c", SERVER_TUN, "-t", secs + 1.5, "-J", "-p", "5201"],
                        "lat-iperf", capture=True)
    time.sleep(0.7)
    res = probe(sess, secs, cores, params["probe_pps"])
    bg.communicate(timeout=secs + 15)
    if sink:
        sink.communicate(timeout=secs + 15)
    return res


def tunnel_metrics(res, w, direct_res):
    gib = res["bytes"] / 2 ** 30
    out = {}
    out["goodput_mbps"] = res["mbps"]
    if "pps" in res:
        out["received_pps"] = res["pps"]
    out["cpu_s_per_gib"] = w["cpu_s"] / gib if gib > 0 else None
    packets = max(w["tun_packets"], 1)
    out["cpu_us_per_packet"] = w["cpu_s"] / packets * 1e6
    return out


METRIC_DEFS = {}


def emit_invalid_units(out, ctx, units, reason):
    for u in units:
        for m in u["metrics"]:
            d = METRIC_DEFS[m]
            out.sample(ctx, u["unit"], m, None, d["label"], d["higher"], d["kind"], valid=False, reason=reason)


def run_tunnel_session(plan, arm, pair, position, session_spec, out):
    layer_spec = plan["layers"]["tunnel"]
    ctx = {"layer": "tunnel", "arm": arm, "pair": pair, "position": position}
    cores = plan["cores"]
    sess = Session(plan, arm, session_spec["veth_mtu"], session_spec.get("tun_mtu"))
    records = []
    try:
        sess.setup()
        direct = {}
        for step in session_spec["steps"]:
            ph = layer_spec["phases"][step["phase"]]
            if ph["kind"] == "latency" or step["netem"]:
                continue
            key = (step["label"], step["phase"])
            p2 = dict(layer_spec)
            p2["phase_s"] = layer_spec["direct_s"]
            direct[key] = run_phase(sess, step["phase"], ph, p2, True, cores)
        sess.netem(None)
        sess.start_tunnel()
        start_echo(sess, False, cores)
        iperf(sess, False, "fwd", layer_spec["warmup_s"], cores)
        env = sess.env()
        for step in session_spec["steps"]:
            sess.check_alive()
            ph = layer_spec["phases"][step["phase"]]
            sess.netem(step["netem"])
            time.sleep(0.3)
            unit = "tunnel/%s/%s" % (step["label"], step["phase"])
            if ph["kind"] == "latency":
                res = latency_phase(sess, step["phase"], ph, layer_spec, cores)
                for m in ph["metrics"]:
                    d = METRIC_DEFS[m]
                    out.sample(ctx, unit, m, res[m], d["label"], d["higher"], d["kind"], extra=res, env=env)
                continue
            res, w = window(sess, lambda: run_phase(sess, step["phase"], ph, layer_spec, False, cores))
            sess.check_alive()
            d = direct.get((step["label"], step["phase"]))
            metrics = tunnel_metrics(res, w, d)
            key = "pps" if ph.get("primary") == "pps" else "mbps"
            ratio = d[key] / max(res[key], 1e-9) if d else None
            reasons = []
            if res["gen_cpu_frac"] >= layer_spec["generator_saturation"] or res.get("gen_behind_schedule"):
                reasons.append("generator saturated (cpu fraction %.2f)" % res["gen_cpu_frac"])
            if d and ratio < layer_spec["ceiling_ratio"]:
                reasons.append("direct ceiling %.2fx of tunnel result, below %.2fx" % (ratio, layer_spec["ceiling_ratio"]))
            extra = dict(res)
            extra.update({"window": w, "direct": d, "direct_over_tunnel": ratio,
                          "tool_saturated_before_ceiling": bool(reasons)})
            for m in ph["metrics"]:
                v = metrics.get(m)
                md = METRIC_DEFS[m]
                bad = list(reasons)
                if v is None:
                    bad.append("no delivered bytes for %s" % m)
                out.sample(ctx, unit, m, v, md["label"], md["higher"], md["kind"], valid=not bad,
                           reason="; ".join(bad) or None, extra=extra, env=env)
            for extra_metric in ("loss_pct", "duplicates", "reordered", "offered_mbps"):
                if extra_metric in res:
                    out.sample(ctx, unit, extra_metric, res[extra_metric], "", False, "timing", gate=False,
                               extra={}, env=env)
        reasons = sess.stop()
        if reasons:
            raise Invalid("; ".join(reasons))
    except Invalid as e:
        sess.stop()
        emit_invalid_units(out, ctx, session_spec["units"], str(e))
    except (subprocess.TimeoutExpired, ValueError, KeyError, OSError) as e:
        sess.stop()
        emit_invalid_units(out, ctx, session_spec["units"], "session error: %r" % (e,))
    finally:
        sess.teardown()


def run_tunnel(plan, pair, out):
    for position, arm in enumerate(arm_order(pair)):
        for session_spec in plan["layers"]["tunnel"]["sessions"]:
            run_tunnel_session(plan, arm, pair, position, session_spec, out)


def snapshot(sess):
    c = proc_mem(sess.pid("client"))
    s = proc_mem(sess.pid("server"))
    comb = {k: c[k] + s[k] for k in c}
    return {"client": c, "server": s, "combined": comb}


def emit_mem(out, ctx, session_id, phase, snap, env, phase_metrics):
    for endpoint, vals in snap.items():
        for m in phase_metrics[phase]:
            out.sample(ctx, "memory/%s/%s/%s" % (session_id, endpoint, phase), m, vals[m], "kB", False, "memory",
                       extra={"all": vals}, env=env)


def run_memory_session(plan, arm, pair, position, spec, out):
    layer = plan["layers"]["memory"]
    ctx = {"layer": "memory", "arm": arm, "pair": pair, "position": position}
    cores = plan["cores"]
    sess = Session(plan, arm, spec["veth_mtu"], spec.get("tun_mtu"))
    pm = layer["phase_metrics"]
    try:
        sess.setup()
        sess.netem(spec.get("netem"))
        sess.start_tunnel()
        time.sleep(layer["settle_s"])
        env = sess.env()
        sid = spec["id"]
        if spec["kind"] == "idle_load":
            emit_mem(out, ctx, sid, "idle", snapshot(sess), env, pm)
            iperf(sess, False, "fwd", layer["load_s"], cores)
            sess.check_alive()
            emit_mem(out, ctx, sid, "load", snapshot(sess), env, pm)
            time.sleep(layer["drain_s"])
            emit_mem(out, ctx, sid, "after_load_drain", snapshot(sess), env, pm)
        else:
            blast = sess.spawn("c", cores["gen_client"],
                               ["udpprobe", "blast", "--dst", SERVER_TUN, "--port", "9000", "--size", spec["payload"],
                                "--pps", spec["pps"], "--secs", layer["reorder_s"]], "mem-blast", capture=True)
            sink = sess.spawn("s", cores["gen_server"],
                              ["udpprobe", "sink", "--bind", SERVER_TUN, "--port", "9000", "--secs",
                               layer["reorder_s"] + 6, "--idle-s", "0.7"], "mem-sink", capture=True)
            blast.communicate(timeout=layer["reorder_s"] + 15)
            sink_out, _ = sink.communicate(timeout=layer["reorder_s"] + 15)
            sess.check_alive()
            emit_mem(out, ctx, sid, "reorder", snapshot(sess), env, pm)
            time.sleep(layer["drain_s"])
            emit_mem(out, ctx, sid, "after_reorder_drain", snapshot(sess), env, pm)
            s = json.loads(sink_out)
            for m in ("received", "lost", "duplicates", "reordered"):
                out.sample(ctx, "memory/%s/traffic" % sid, m, s[m], "pkts", False, "memory", gate=False, env=env)
        for endpoint, role in (("client", "client"), ("server", "server")):
            g = env["granted"][role]
            for m in ("rcvbuf", "sndbuf"):
                out.sample(ctx, "memory/%s/%s/sockbuf" % (sid, endpoint), m, g[m], "bytes", False, "memory",
                           gate=False, env=env)
        rs = sess.stop()
        if rs:
            raise Invalid("; ".join(rs))
    except Invalid as e:
        sess.stop()
        emit_invalid_units(out, ctx, spec["units"], str(e))
    except (subprocess.TimeoutExpired, ValueError, KeyError, OSError) as e:
        sess.stop()
        emit_invalid_units(out, ctx, spec["units"], "session error: %r" % (e,))
    finally:
        sess.teardown()


def run_memory(plan, pair, out):
    for position, arm in enumerate(arm_order(pair)):
        for spec in plan["layers"]["memory"]["sessions"]:
            run_memory_session(plan, arm, pair, position, spec, out)


def run_tool(argv, cpu):
    r = subprocess.run(["taskset", "-c", str(cpu)] + [str(a) for a in argv], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise Invalid("%s exited %d: %s" % (argv[0], r.returncode, r.stderr[-200:]))
    return json.loads(r.stdout.strip().splitlines()[-1])


def run_crypto(plan, pair, out):
    spec = plan["layers"]["crypto"]
    for op in spec["ops"]:
        for size in spec["sizes"]:
            for position, arm in enumerate(arm_order(pair)):
                ctx = {"layer": "crypto", "arm": arm, "pair": pair, "position": position}
                unit = "crypto/%s/%d" % (op, size)
                binary = plan["arms"][arm]["crypto_bench"]
                try:
                    if not binary:
                        raise Invalid(plan["arms"][arm]["crypto_bench_unavailable"])
                    r = run_tool([binary, "--op", op, "--size", size, "--ms", spec["ms"], "--warmup-ms", spec["warmup_ms"],
                                  "--seed", plan["seed"]], plan["cores"]["micro"])
                    out.sample(ctx, unit, "ns_per_op", r["ns_per_op"], "ns", False, "timing", extra=r)
                except Invalid as e:
                    out.sample(ctx, unit, "ns_per_op", None, "ns", False, "timing", valid=False, reason=str(e))


def run_packet(plan, pair, out):
    spec = plan["layers"]["packet"]
    for sc in spec["scenarios"]:
        for position, arm in enumerate(arm_order(pair)):
            ctx = {"layer": "packet", "arm": arm, "pair": pair, "position": position}
            unit = "packet/%s" % sc["name"]
            binary = plan["arms"][arm]["packet_bench"]
            try:
                if not binary:
                    raise Invalid(plan["arms"][arm]["packet_bench_unavailable"])
                r = run_tool([binary, "--scenario", sc["name"], "--packets", sc["packets"], "--reps", sc["reps"],
                              "--payload", sc["payload"], "--seed", plan["seed"]], plan["cores"]["micro"])
                out.sample(ctx, unit, "ns_per_packet", r["ns_per_packet"], "ns", False, "timing", extra=r)
                out.sample(ctx, unit, "alloc_count", r["alloc_count"], "allocs", False, "count", extra=r)
                out.sample(ctx, unit, "alloc_bytes", r["alloc_bytes"], "bytes", False, "count", extra=r)
                out.sample(ctx, unit, "retained_kb", r["retained_kb"], "kB", False, "memory", extra=r)
            except Invalid as e:
                for m, k in (("ns_per_packet", "timing"), ("alloc_count", "count"), ("alloc_bytes", "count"),
                             ("retained_kb", "memory")):
                    out.sample(ctx, unit, m, None, "", False, k, valid=False, reason=str(e))


def cmd_meta(plan):
    def first(cmd):
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return (r.stdout.strip().splitlines() or [r.stderr.strip()])[0] if (r.stdout.strip() or r.stderr.strip()) else None

    cpuinfo = open("/proc/cpuinfo").read()
    features = re.search(r"Features\s*:\s*(.*)", cpuinfo)
    thermal = os.path.isdir("/sys/class/thermal") and os.listdir("/sys/class/thermal") or None
    meta = {
        "kernel": first("uname -r"),
        "machine": first("uname -m"),
        "libc": first("ldd --version"),
        "gcc": first("gcc --version"),
        "cpu_count": os.cpu_count(),
        "cpu_features": features.group(1) if features else None,
        "lscpu": {k.strip(): v.strip() for k, _, v in (l.partition(":") for l in
                  subprocess.run("lscpu", capture_output=True, text=True).stdout.splitlines()) if k.strip()},
        "affinity": sorted(os.sched_getaffinity(0)),
        "pins": plan["cores"],
        "loadavg": open("/proc/loadavg").read().strip(),
        "iperf3": first("iperf3 --version"),
        "udpprobe": first(plan["tools"]["udpprobe"] + " --version"),
        "tc": first("tc -V"),
        "ethtool": "available" if subprocess.run("which ethtool", shell=True, capture_output=True).returncode == 0 else "unavailable",
        "thermal": thermal or "unavailable: no /sys/class/thermal in the Linux guest",
        "freq": "unavailable: guest exposes fixed CPU max MHz only",
        "rustc": first("rustc -V"),
        "cargo": first("cargo -V"),
        "rustc_host": first("rustc -vV | sed -n 's/^host: //p'"),
        "sysctl_rmem_max": first("cat /proc/sys/net/core/rmem_max"),
        "sysctl_wmem_max": first("cat /proc/sys/net/core/wmem_max"),
    }
    print(json.dumps(meta))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", required=True)
    ap.add_argument("--layer", required=True)
    ap.add_argument("--pair", type=int, default=0)
    ap.add_argument("--out")
    a = ap.parse_args()
    with open(a.plan) as f:
        plan = json.load(f)
    os.environ["PATH"] = os.path.dirname(plan["tools"]["udpprobe"]) + ":" + os.environ["PATH"]
    plan["cores"] = pick_cores()
    METRIC_DEFS.update(plan["metric_defs"])
    if a.layer == "meta":
        cmd_meta(plan)
        return
    out = Out(a.out)
    {"crypto": run_crypto, "packet": run_packet, "tunnel": run_tunnel, "memory": run_memory}[a.layer](plan, a.pair, out)


if __name__ == "__main__":
    main()
