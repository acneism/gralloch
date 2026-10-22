#!/usr/bin/env python3
"""Run the gralloch Frida tracer against a sample and write trace.json.

!!! RUN ONLY INSIDE THE ANALYSIS VM !!!
This EXECUTES the sample. Preconditions (your responsibility, per the spec):
  - a dedicated Windows analysis VM on an active snapshot (roll back afterwards),
  - network off or faked (FakeNet-NG) -- mandatory for the `malware` profile,
  - the sample and this script transferred into the VM (manual for `malware`).
Never run this on the host. The host-side `dynamic_import` tool then normalizes
the resulting trace.json; copy trace.json back to the case's artifacts/.

Usage (inside the VM):
  python run-frida.py --sample <sample> --script frida_trace.js \
      --out trace.json --timeout 20 --yes-run-in-vm
"""
import argparse
import json
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", required=True, help="path to the sample to execute (in the VM)")
    ap.add_argument("--script", required=True, help="path to frida_trace.js")
    ap.add_argument("--out", required=True, help="output trace.json path")
    ap.add_argument("--timeout", type=int, default=20, help="seconds to trace before stopping")
    ap.add_argument("--yes-run-in-vm", action="store_true",
                    help="required confirmation that this is the analysis VM")
    args = ap.parse_args()

    if not args.yes_run_in_vm:
        sys.exit("refusing to run: pass --yes-run-in-vm to confirm this is the VM, not the host")

    import frida  # imported late so the host can read/lint this file without frida installed

    events = []

    def on_message(message, data):
        if message.get("type") == "send":
            payload = message.get("payload") or {}
            if payload.get("t") == "gralloch":
                events.append({
                    "cat": payload.get("cat", "other"),
                    "api": payload.get("api", ""),
                    "detail": payload.get("detail", ""),
                })
        elif message.get("type") == "error":
            events.append({"cat": "meta", "api": "frida-error", "detail": message.get("description", "")})

    pid = frida.spawn([args.sample])
    session = frida.attach(pid)
    script = session.create_script(open(args.script, "r", encoding="utf-8").read())
    script.on("message", on_message)
    script.load()
    frida.resume(pid)
    time.sleep(args.timeout)
    try:
        session.detach()
    except Exception:
        pass
    try:
        frida.kill(pid)
    except Exception:
        pass

    trace = {"tool": "frida", "sample": args.sample, "events": events}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(trace, f, indent=2)
    print("wrote %d events to %s" % (len(events), args.out))


if __name__ == "__main__":
    main()
