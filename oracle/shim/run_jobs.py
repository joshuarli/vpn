import concurrent.futures
import json
import os
import subprocess
import sys

SHIM = "/target/oracle/twice_shim.so"


def snapshot(root):
    snap = {}
    for base, _dirs, names in os.walk(root):
        for name in names:
            path = os.path.join(base, name)
            rel = os.path.relpath(path, root)
            with open(path, "rb") as f:
                data = f.read()
            snap[rel] = (data, os.stat(path).st_mode & 0o7777)
    return snap


def run_job(job_dir):
    with open(os.path.join(job_dir, "job.json")) as f:
        meta = json.load(f)
    sandbox = os.path.join(job_dir, "sb")
    trace = os.path.join(job_dir, "trace.jsonl")
    if os.path.exists(trace):
        os.unlink(trace)
    before = snapshot(sandbox)
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "LD_PRELOAD": SHIM,
        "TWICE_SHIM_SCRIPT": os.path.join(job_dir, "script"),
        "TWICE_SHIM_OUT": trace,
    }
    timed_out = False
    spawn_error = None
    try:
        proc = subprocess.run(
            ["twice"] + meta["argv"],
            executable=meta["bin"],
            cwd=sandbox,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=meta.get("timeout_s", 120),
        )
        rc, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        rc, out, err = None, exc.stdout or b"", exc.stderr or b""
    except OSError as exc:
        spawn_error = str(exc)
        rc, out, err = None, b"", b""
    after = snapshot(sandbox)
    files = []
    for rel in sorted(after):
        data, mode = after[rel]
        if rel not in before or before[rel] != (data, mode):
            files.append({"path": rel, "hex": data.hex(), "mode": "%04o" % mode})
    with open(os.path.join(job_dir, "stdout"), "wb") as f:
        f.write(out)
    with open(os.path.join(job_dir, "stderr"), "wb") as f:
        f.write(err)
    if not os.path.exists(trace):
        open(trace, "wb").close()
    with open(os.path.join(job_dir, "result.json"), "w") as f:
        json.dump(
            {"returncode": rc, "timeout": timed_out, "spawn_error": spawn_error, "files": files}, f
        )


def main():
    run_dir = sys.argv[1]
    jobs = sorted(
        os.path.join(run_dir, d)
        for d in os.listdir(run_dir)
        if os.path.exists(os.path.join(run_dir, d, "job.json"))
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(run_job, jobs))


main()
