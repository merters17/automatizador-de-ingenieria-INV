"""Simula la CLI de rea según FAKE_REA_MODE. Solo para pruebas del automatizador."""
import json
import os
import signal
import sys
import time

mode = os.environ.get("FAKE_REA_MODE", "ok")
argv = sys.argv[1:]

def progress(msg, seq):
    sys.stderr.write(json.dumps({"rea_progress": {"phase": "p", "completed": seq, "total": 2, "message": msg, "sequence": seq}}) + "\n")
    sys.stderr.flush()

if mode == "ok":
    progress("first", 1)
    progress("second", 2)
    print(json.dumps({"argv": argv, "evidence_id": "ev_test"}))
    sys.exit(0)
if mode == "error":
    print(json.dumps({"error": "Analysis failed", "code": "target_unavailable"}))
    sys.exit(1)
if mode == "exit0err":
    print(json.dumps({"error": "Analysis failed", "code": "x"}))
    sys.exit(0)
if mode == "badjson":
    print("this is not json")
    sys.exit(0)
if mode == "noerror":
    print("plain failure text")
    sys.exit(1)
if mode == "exit5":
    sys.exit(5)
if mode == "sleep":
    time.sleep(60)
    sys.exit(0)
if mode == "selfkill":
    os.kill(os.getpid(), signal.SIGKILL)
if mode == "bigout":
    chunk = "x" * 1024
    for _ in range(4096):
        sys.stdout.write(chunk)
    sys.exit(0)
if mode == "managed_notmanaged":
    print(json.dumps({"operation": "inspect_managed_artifact", "normalized_result": {"classification": {"status": "not-managed"}}}))
    sys.exit(0)
if mode == "managed_ok":
    print(json.dumps({"operation": "inspect_managed_artifact", "normalized_result": {"classification": {"status": "managed"}}}))
    sys.exit(0)
if mode == "js_empty":
    print(json.dumps({"evidence_id": "ev_js", "summary": {"statistics": {"relevant_files": 0}}}))
    sys.exit(0)
sys.exit(3)
