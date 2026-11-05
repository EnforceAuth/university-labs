"""Regression self-test for the Python PEP (Check QA probes, 2026-11-05).
Usage: python3 pep_selftest.py [path/to/pep_python.py]   exit 0 = all green."""
import http.server, importlib.util, json, sys, threading, time

path = sys.argv[1] if len(sys.argv) > 1 else "pep_python.py"
spec = importlib.util.spec_from_file_location("pep", path); pep = importlib.util.module_from_spec(spec); sys.modules["pep"] = pep; spec.loader.exec_module(pep)

CASES = {  # name: (status, body, delay_s, expected_allow)
    "bool_true": (200, '{"result": true}', 0, True),
    "bool_false": (200, '{"result": false}', 0, False),
    "missing_result": (200, '{}', 0, False),
    "null_result": (200, '{"result": null}', 0, False),
    "string_true": (200, '{"result": "true"}', 0, False),
    "number_one": (200, '{"result": 1}', 0, False),
    "obj_allow_string_false": (200, '{"result": {"allow": "false"}}', 0, False),
    "obj_allow_one": (200, '{"result": {"allow": 1}}', 0, False),
    "obj_allow_true": (200, '{"result": {"allow": true}}', 0, False),
    "top_level_list": (200, '[]', 0, False),
    "top_level_null": (200, 'null', 0, False),
    "malformed_json": (200, '{"result": tru', 0, False),
    "http_500": (500, '{"result": true}', 0, False),
    "http_204": (204, '', 0, False),
    "trailing_garbage": (200, '{"result": true} garbage', 0, False),
    "second_document": (200, '{"result": true}{"result": false}', 0, False),
    "list_result": (200, '{"result": [true]}', 0, False),
    "http_201_true": (201, '{"result": true}', 0, False),
    "key_Result_case": (200, '{"Result": true}', 0, False),
    "key_RESULT_case": (200, '{"RESULT": true}', 0, False),
    "timeout": (200, '{"result": true}', 1.0, False),
}

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        status, body, delay, _ = CASES[self.path.rsplit("/", 1)[-1]]
        time.sleep(delay)
        self.send_response(status); self.end_headers()
        if body: self.wfile.write(body.encode())

srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
url = f"http://127.0.0.1:{srv.server_address[1]}"
fails = 0
for name, (_, _, _, want) in CASES.items():
    try:
        got = pep.ask_pdp(url, f"probe/{name}", {"action": "read"}, timeout_s=0.3).allow
        res = "PASS" if got is want else f"FAIL (allow={got})"
    except Exception as e:
        res = f"FAIL (uncaught {type(e).__name__})"
    fails += res != "PASS"; print(f"{name}: {res}")
dead = pep.ask_pdp("http://127.0.0.1:1", "x", {}, timeout_s=0.3).allow
print("dead_port:", "PASS" if dead is False else "FAIL"); fails += dead is not False
n = len(CASES) + 1
print(f"{'PASS' if not fails else 'FAIL'}: {n-fails} pass, {fails} fail of {n}")
sys.exit(1 if fails else 0)
