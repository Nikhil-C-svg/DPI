"""Serve the DPI dashboard and run the C++ analyzer on local PCAP files."""

import argparse
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import IPv4Address
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
WEB = Path(__file__).resolve().parent
LIMIT = 16 * 1024 * 1024
APP_NAMES = (
    "Unknown", "HTTP", "HTTPS", "DNS", "TLS", "QUIC", "Google", "Facebook",
    "YouTube", "Twitter/X", "Instagram", "Netflix", "Amazon", "Microsoft",
    "Apple", "WhatsApp", "Telegram", "TikTok", "Spotify", "Zoom", "Discord",
    "GitHub", "Cloudflare",
)
ASSETS = {
    "/": ("index.html", "text/html"),
    "/style.css": ("style.css", "text/css"),
    "/app.js": ("app.js", "text/javascript"),
}


def validate_capture(data):
    if not 24 <= len(data) <= LIMIT:
        raise ValueError("Choose a PCAP file between 24 bytes and 16 MiB.")
    magic, major, minor, _, _, snaplen, link = struct.unpack_from("<IHHIIII", data)
    if (magic, major, minor, link) != (0xA1B2C3D4, 2, 4, 1) or not snaplen:
        raise ValueError("Use Ethernet PCAP 2.4 in little-endian, microsecond format.")
    offset = 24
    while offset < len(data):
        if len(data) - offset < 16:
            raise ValueError("The capture ends inside a packet header.")
        _, _, captured, original = struct.unpack_from("<IIII", data, offset)
        offset += 16
        if captured > min(snaplen, original, 65535, len(data) - offset):
            raise ValueError("The capture contains an invalid or truncated packet record.")
        offset += captured


def rule_arguments(query):
    keys = {"ip": "--block-ip", "app": "--block-app", "domain": "--block-domain"}
    if query.keys() - (keys.keys() | {"sample"}):
        raise ValueError("Unknown analysis option.")
    args = []
    for field, flag in keys.items():
        for value in query.get(field, []):
            if field == "ip":
                try:
                    IPv4Address(value)
                except ValueError:
                    raise ValueError("Enter a valid source IPv4 address.") from None
            elif field == "app" and value not in APP_NAMES:
                raise ValueError("Choose an application from the list.")
            elif field == "domain" and not re.fullmatch(r"[A-Za-z0-9._-]{1,253}", value):
                raise ValueError("Enter a domain or substring using letters, numbers, dots or hyphens.")
            args.extend((flag, value))
    return args


def analyze(engine, data, args):
    validate_capture(data)
    with tempfile.TemporaryDirectory(prefix="dpi-dashboard-") as directory:
        work = Path(directory)
        (work / "input.pcap").write_bytes(data)
        run = subprocess.run(
            [str(engine), "input.pcap", "filtered.pcap", "--report-json", "report.json", *args],
            cwd=work,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=45,
            check=False,
        )
        if run.returncode:
            raise RuntimeError("The C++ analyzer could not process this capture.")
        report_path = work / "report.json"
        if not report_path.is_file():
            raise RuntimeError("Rebuild packet_analyzer from the dashboard branch to enable JSON reports.")
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeError) as error:
            raise RuntimeError("The analyzer returned an unreadable report.") from error
        filtered = (work / "filtered.pcap").read_bytes()
        return {"report": report, "capture": base64.b64encode(filtered).decode("ascii")}


class Dashboard(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def send_bytes(self, status, body, media_type):
        self.send_response(status)
        self.send_header("Content-Type", media_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        )
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status, value):
        self.send_bytes(status, json.dumps(value).encode("utf-8"), "application/json")

    def do_GET(self):
        if self.headers.get("Host") != self.server.local_host:
            self.send_json(403, {"error": "Open the dashboard at its loopback address."})
            return
        asset = ASSETS.get(self.path)
        if asset is None:
            self.send_json(404, {"error": "Page not found."})
            return
        filename, media_type = asset
        self.send_bytes(200, (WEB / filename).read_bytes(), f"{media_type}; charset=utf-8")

    def do_POST(self):
        if (
            self.headers.get("Host") != self.server.local_host
            or self.headers.get("Origin") != f"http://{self.server.local_host}"
            or self.headers.get("Content-Type") != "application/octet-stream"
        ):
            self.send_json(403, {"error": "Start the analysis from the local dashboard."})
            return
        route = urlsplit(self.path)
        if route.path != "/api/analyze":
            self.send_json(404, {"error": "Endpoint not found."})
            return
        try:
            size = int(self.headers.get("Content-Length", "-1"))
            if not 0 <= size <= LIMIT or self.headers.get("Transfer-Encoding"):
                raise ValueError("The dashboard accepts capture files up to 16 MiB.")
            query = parse_qs(route.query, max_num_fields=16)
            args = rule_arguments(query)
            if query.get("sample") == ["1"] and size == 0:
                data = (ROOT / "test_dpi.pcap").read_bytes()
            elif "sample" not in query and size:
                data = self.rfile.read(size)
                if len(data) != size:
                    raise ValueError("The capture upload was interrupted.")
            else:
                raise ValueError("Choose a capture or use the bundled sample.")
            result = analyze(self.server.engine, data, args)
        except ValueError as error:
            self.send_json(400, {"error": str(error)})
        except TimeoutError:
            self.send_json(408, {"error": "The capture upload timed out. Try again."})
        except subprocess.TimeoutExpired:
            self.send_json(504, {"error": "Analysis timed out. Try a smaller capture."})
        except RuntimeError as error:
            self.send_json(500, {"error": str(error)})
        except OSError:
            self.send_json(500, {"error": "Could not run the analyzer or read its files."})
        else:
            self.send_json(200, result)

    def log_request(self, code="-", size="-"):
        # Rule values and capture names are omitted from the terminal log.
        self.log_message("%s %s", self.command, code)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, required=True, help="path to the compiled packet_analyzer")
    parser.add_argument("--port", type=int, default=8000, help="loopback port (default: 8000)")
    args = parser.parse_args()
    engine = args.engine.resolve()
    if not engine.is_file():
        parser.error("packet_analyzer was not found. Build the C++ engine first.")
    if not 1 <= args.port <= 65535:
        parser.error("choose a port between 1 and 65535")
    try:
        with HTTPServer(("127.0.0.1", args.port), Dashboard) as server:
            server.engine = engine
            server.local_host = f"127.0.0.1:{args.port}"
            print(f"Open http://{server.local_host}", flush=True)
            server.serve_forever()
    except KeyboardInterrupt:
        pass
    except OSError as error:
        parser.exit(1, f"Could not start the dashboard: {error}\n")


if __name__ == "__main__":
    main()
