#!/usr/bin/env python3
"""XLink Kai UDP traffic monitor — Prometheus exporter.

Captures UDP packets on the Docker bridge interface for XLink Kai
ports (30000, 34523) and calculates per-peer jitter, packet rate,
and throughput. Exposes metrics at /metrics for Prometheus scraping.

Runs with network_mode: host to access the bridge interface directly.
"""

import json
import os
import re
import subprocess
import threading
import time
import urllib.request
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler

BRIDGE_INTERFACE = os.environ.get("BRIDGE_INTERFACE", "eth0")
LOCAL_IP = os.environ.get("XLINKKAI_IP", "172.20.0.25")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "9428"))
JITTER_WINDOW = 60  # seconds
PING_INTERVAL = 10  # seconds between ping rounds
PING_COUNT = 3      # pings per peer per round
PEER_EXPIRY = 30    # seconds — drop peers with no traffic for 30 seconds
SCORE_WARMUP = 30   # seconds — ignore first 30s after peer connects
SCORE_COOLDOWN = 30 # seconds — stop scoring 30s after last packet


class PeerStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.rx_times = []   # [(timestamp, size, port)]
        self.tx_times = []
        self.rx_packets = 0
        self.tx_packets = 0
        self.rx_bytes = 0
        self.tx_bytes = 0
        self.first_seen = 0.0 # timestamp of very first packet
        self.last_seen = 0.0  # timestamp of most recent packet (rx or tx)

    def add_rx(self, ts, size, port):
        with self.lock:
            if self.first_seen == 0.0:
                self.first_seen = ts
            self.rx_times.append((ts, size, port))
            self.rx_packets += 1
            self.rx_bytes += size
            self.last_seen = max(self.last_seen, ts)
            self._trim(self.rx_times, ts)

    def add_tx(self, ts, size, port):
        with self.lock:
            if self.first_seen == 0.0:
                self.first_seen = ts
            self.tx_times.append((ts, size, port))
            self.tx_packets += 1
            self.tx_bytes += size
            self.last_seen = max(self.last_seen, ts)
            self._trim(self.tx_times, ts)

    def _trim(self, lst, now):
        cutoff = now - JITTER_WINDOW
        while lst and lst[0][0] < cutoff:
            lst.pop(0)

    @staticmethod
    def _jitter(timestamps):
        """RFC 3550-style inter-arrival jitter (mean absolute deviation)."""
        if len(timestamps) < 2:
            return 0.0
        deltas = [timestamps[i][0] - timestamps[i - 1][0]
                  for i in range(1, len(timestamps))]
        mean = sum(deltas) / len(deltas)
        return sum(abs(d - mean) for d in deltas) / len(deltas)

    def snapshot(self):
        with self.lock:
            now = time.time()
            cutoff = now - JITTER_WINDOW
            rx = [(t, s, p) for t, s, p in self.rx_times if t > cutoff]
            tx = [(t, s, p) for t, s, p in self.tx_times if t > cutoff]
            elapsed = JITTER_WINDOW
            return {
                "rx_jitter": self._jitter(rx),
                "tx_jitter": self._jitter(tx),
                "rx_pps": len(rx) / elapsed,
                "tx_pps": len(tx) / elapsed,
                "rx_bps": sum(s for _, s, _ in rx) / elapsed,
                "tx_bps": sum(s for _, s, _ in tx) / elapsed,
                "rx_packets_total": self.rx_packets,
                "tx_packets_total": self.tx_packets,
                "rx_bytes_total": self.rx_bytes,
                "tx_bytes_total": self.tx_bytes,
            }


peers = defaultdict(PeerStats)
local_ips = set()

# Player names: ip -> custom name or auto-assigned "Player N"
PLAYERS_FILE = os.environ.get("PLAYERS_FILE", "/app/players.json")
player_names = {}   # loaded from players.json
player_aliases = {} # auto-assigned for unknown IPs
player_counter = 0
player_lock = threading.Lock()


def _load_player_names():
    """Load IP -> name mappings from players.json."""
    global player_names
    try:
        with open(PLAYERS_FILE) as f:
            player_names = json.load(f)
        print(f"Loaded {len(player_names)} player name(s) from {PLAYERS_FILE}")
    except FileNotFoundError:
        player_names = {}
    except Exception as e:
        print(f"Warning: could not load {PLAYERS_FILE}: {e}")
        player_names = {}


def get_player_alias(ip):
    """Return a named alias if known, otherwise auto-assign 'Player N'."""
    # Check the names file first (no lock needed, read-only after load)
    if ip in player_names:
        return player_names[ip]
    global player_counter
    with player_lock:
        if ip not in player_aliases:
            player_counter += 1
            player_aliases[ip] = f"Player {player_counter}"
        return player_aliases[ip]


# GeoIP cache: ip -> {"country": "US", "city": "Ann Arbor"}
geo_cache = {}
geo_lock = threading.Lock()


def _geoip_lookup(ip):
    """Background GeoIP lookup via ip-api.com (free, no key needed)."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,countryCode"
        req = urllib.request.urlopen(url, timeout=5)
        data = json.loads(req.read())
        if data.get("status") == "success":
            info = {"country": data.get("countryCode", "??"),
                    "city": data.get("city", "Unknown")}
        else:
            info = {"country": "??", "city": "Unknown"}
    except Exception:
        info = {"country": "??", "city": "Unknown"}
    with geo_lock:
        geo_cache[ip] = info


def get_geo(ip):
    """Return cached geo info, kicking off a background lookup if needed."""
    with geo_lock:
        if ip in geo_cache:
            return geo_cache[ip]
    # First time seeing this peer — start async lookup
    geo_cache[ip] = {"country": "??", "city": "resolving..."}
    threading.Thread(target=_geoip_lookup, args=(ip,), daemon=True).start()
    return geo_cache[ip]

# ICMP ping results: ip -> {"rtt": float_seconds, "loss": float_percent}
ping_results = {}
ping_lock = threading.Lock()

# Matches both standard ping and busybox ping RTT summary lines:
#   rtt min/avg/max/mdev = 1.0/2.0/3.0/0.5 ms   (standard)
#   round-trip min/avg/max = 1.0/2.0/3.0 ms       (busybox)
PING_RTT_RE = re.compile(r"(?:rtt|round-trip) min/avg/max(?:/\S+)? = [\d.]+/([\d.]+)/")
PING_LOSS_RE = re.compile(r"(\d+)% packet loss")


def _ping_peer(ip):
    """Ping a single peer and return (rtt_seconds, loss_percent)."""
    try:
        result = subprocess.run(
            ["ping", "-c", str(PING_COUNT), "-W", "2", ip],
            capture_output=True, text=True, timeout=15
        )
        output = result.stdout

        loss = 100.0
        m = PING_LOSS_RE.search(output)
        if m:
            loss = float(m.group(1))

        rtt = 0.0
        m = PING_RTT_RE.search(output)
        if m:
            rtt = float(m.group(1)) / 1000.0  # ms -> seconds

        return rtt, loss
    except Exception:
        return 0.0, 100.0


def _expire_peers():
    """Remove peers with no traffic in the last PEER_EXPIRY seconds."""
    now = time.time()
    expired = [ip for ip, s in peers.items()
               if s.last_seen > 0 and (now - s.last_seen) > PEER_EXPIRY]
    for ip in expired:
        del peers[ip]
        with ping_lock:
            ping_results.pop(ip, None)
        with geo_lock:
            geo_cache.pop(ip, None)
        with player_lock:
            player_aliases.pop(ip, None)
    if expired:
        print(f"Expired {len(expired)} stale peer(s): {', '.join(expired)}")


def ping_loop():
    """Background loop that pings active peers and expires stale ones."""
    while True:
        time.sleep(PING_INTERVAL)
        _expire_peers()
        current_peers = list(peers.keys())
        for ip in current_peers:
            rtt, loss = _ping_peer(ip)
            with ping_lock:
                ping_results[ip] = {"rtt": rtt, "loss": loss}


def _score_component(value, thresholds):
    """Map a value to 0-100 using piecewise-linear thresholds.

    thresholds: list of (boundary, score) pairs in ascending order by boundary.
    Values below the first boundary get the first score; above the last get 0.
    """
    if value <= thresholds[0][0]:
        return thresholds[0][1]
    for i in range(1, len(thresholds)):
        lo_val, lo_score = thresholds[i - 1]
        hi_val, hi_score = thresholds[i]
        if value <= hi_val:
            t = (value - lo_val) / (hi_val - lo_val)
            return lo_score + t * (hi_score - lo_score)
    return 0.0


MIN_PPS_FOR_JITTER = 3  # Below this, jitter is unreliable (idle/keepalive)


def connection_score(rtt_s, jitter_s, loss_pct, has_icmp, rx_pps):
    """Compute a 0-100 gaming connection quality score.

    Thresholds tuned for original Xbox system-link gaming:
      RTT:    <30ms perfect, >200ms unplayable
      Jitter: <5ms perfect,  >50ms unplayable
      Loss:   0% perfect,    >5% unplayable
    """
    rtt_ms = rtt_s * 1000.0
    jitter_ms = jitter_s * 1000.0
    active = rx_pps >= MIN_PPS_FOR_JITTER

    rtt_score = _score_component(rtt_ms, [
        (0, 100), (30, 95), (60, 80), (100, 60), (150, 35), (200, 10), (300, 0)
    ])
    jitter_score = _score_component(jitter_ms, [
        (0, 100), (5, 90), (15, 70), (30, 40), (50, 10), (80, 0)
    ])
    loss_score = _score_component(loss_pct, [
        (0, 100), (0.5, 75), (1, 55), (3, 25), (5, 5), (10, 0)
    ])

    if has_icmp and active:
        # Full data: RTT 35%, Jitter 35%, Loss 30%
        return 0.35 * rtt_score + 0.35 * jitter_score + 0.30 * loss_score
    elif has_icmp:
        # ICMP available but idle — grade on RTT + loss only
        return 0.55 * rtt_score + 0.45 * loss_score
    else:
        # ICMP blocked — grade on RX jitter (still meaningful from keepalives)
        return jitter_score


def score_to_grade(score):
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 55: return "C"
    if score >= 35: return "D"
    return "F"


# tcpdump line: 1708431381.370039 IP 73.18.119.133.30000 > 172.20.0.25.30000: UDP, length 33
TCPDUMP_RE = re.compile(
    r"^(\d+\.\d+)\s+IP\s+"
    r"(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+"
    r"(\d+\.\d+\.\d+\.\d+)\.(\d+):\s+UDP,\s+length\s+(\d+)"
)


def capture():
    cmd = [
        "tcpdump", "-i", BRIDGE_INTERFACE, "-nn", "-tt", "-l", "--immediate-mode",
        "udp", "and", "(", "port", "30000", "or", "port", "34523", ")",
    ]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    for line in proc.stdout:
        m = TCPDUMP_RE.match(line.strip())
        if not m:
            continue
        ts = float(m.group(1))
        src_ip, src_port = m.group(2), int(m.group(3))
        dst_ip, dst_port = m.group(4), int(m.group(5))
        length = int(m.group(6))

        if src_ip in local_ips:
            peers[dst_ip].add_tx(ts, length, dst_port)
        elif dst_ip in local_ips:
            peers[src_ip].add_rx(ts, length, src_port)


# Metrics with direction label: (metric_name, type, help, rx_snap_key, tx_snap_key)
DIRECTED_METRICS = [
    ("xlink_jitter_seconds", "gauge", "Inter-arrival jitter", "rx_jitter", "tx_jitter"),
    ("xlink_pps", "gauge", "Packets per second", "rx_pps", "tx_pps"),
    ("xlink_throughput_bytes_per_second", "gauge", "Throughput", "rx_bps", "tx_bps"),
    ("xlink_packets_total", "counter", "Total packets", "rx_packets_total", "tx_packets_total"),
    ("xlink_bytes_total", "counter", "Total bytes", "rx_bytes_total", "tx_bytes_total"),
]


class Handler(BaseHTTPRequestHandler):
    def _players_page(self, saved=False):
        """Render the player naming form."""
        rows = []
        for peer_ip in sorted(peers.keys()):
            snap = peers[peer_ip].snapshot()
            if snap["rx_packets_total"] == 0:
                continue
            geo = get_geo(peer_ip)
            current = player_names.get(peer_ip, "")
            auto = get_player_alias(peer_ip)
            loc = f"{geo['city']}, {geo['country']}"
            rows.append(
                f'<tr>'
                f'<td style="padding:8px;color:#999">{peer_ip}</td>'
                f'<td style="padding:8px">{loc}</td>'
                f'<td style="padding:8px;color:#666">{auto}</td>'
                f'<td style="padding:8px">'
                f'<input name="{peer_ip}" value="{current}" '
                f'placeholder="{auto}" '
                f'style="background:#222;color:#fff;border:1px solid #555;'
                f'padding:6px 10px;border-radius:4px;width:200px;font-size:14px">'
                f'</td></tr>'
            )
        banner = ""
        if saved:
            banner = ('<div style="background:#2d5a2d;color:#8f8;padding:10px;'
                      'border-radius:6px;margin-bottom:16px">Saved!</div>')
        html = f"""<!DOCTYPE html>
<html><head><title>XLink Player Names</title></head>
<body style="background:#111;color:#eee;font-family:sans-serif;max-width:700px;margin:40px auto;padding:0 20px">
<h2>XLink Kai — Player Names</h2>
<p style="color:#999">Name your peers. Leave blank to use the auto-assigned alias.
Saved names persist across restarts.</p>
{banner}
<form method="POST" action="/players">
<table style="border-collapse:collapse;width:100%">
<tr style="border-bottom:1px solid #333">
<th style="padding:8px;text-align:left;color:#888">IP</th>
<th style="padding:8px;text-align:left;color:#888">Location</th>
<th style="padding:8px;text-align:left;color:#888">Auto</th>
<th style="padding:8px;text-align:left;color:#888">Custom Name</th></tr>
{''.join(rows)}
</table>
<br>
<button type="submit" style="background:#1a73e8;color:#fff;border:none;
padding:10px 24px;border-radius:6px;font-size:15px;cursor:pointer">
Save Names</button>
</form>
</body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())

    def do_POST(self):
        if self.path != "/players":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        # Parse URL-encoded form: ip=name&ip2=name2
        global player_names
        new_names = {}
        for pair in body.split("&"):
            if "=" not in pair:
                continue
            key, val = pair.split("=", 1)
            key = urllib.request.unquote(key.replace("+", " "))
            val = urllib.request.unquote(val.replace("+", " ")).strip()
            if val:
                new_names[key] = val
        player_names = new_names
        # Persist to disk
        try:
            with open(PLAYERS_FILE, "w") as f:
                json.dump(player_names, f, indent=2)
        except Exception as e:
            print(f"Warning: could not save {PLAYERS_FILE}: {e}")
        self._players_page(saved=True)

    def do_GET(self):
        if self.path == "/players":
            self._players_page()
            return

        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return

        lines = []
        for name, mtype, helptext, _, _ in DIRECTED_METRICS:
            lines.append(f"# HELP {name} {helptext}")
            lines.append(f"# TYPE {name} {mtype}")

        # Collect snapshots and filter to bidirectional peers only.
        # TX-only peers (e.g. orbital servers) are infrastructure, not players.
        snapshots = {}
        for peer_ip, stats in list(peers.items()):
            snap = stats.snapshot()
            if snap["rx_packets_total"] > 0:
                snapshots[peer_ip] = snap

        for peer_ip, snap in snapshots.items():
            geo = get_geo(peer_ip)
            alias = get_player_alias(peer_ip)
            base_labels = (f'peer="{peer_ip}",'
                           f'country="{geo["country"]}",'
                           f'city="{geo["city"]}",'
                           f'player="{alias}"')
            for name, _, _, rx_key, tx_key in DIRECTED_METRICS:
                for direction, key in [("rx", rx_key), ("tx", tx_key)]:
                    val = snap[key]
                    labels = f'{base_labels},direction="{direction}"'
                    fmt = ".6f" if "jitter" in key else (
                        ".2f" if "pps" in key or "bps" in key else "")
                    lines.append(
                        f'{name}{{{labels}}} {val:{fmt}}'
                        if fmt else f'{name}{{{labels}}} {val}'
                    )

        # Ping metrics (RTT + loss) — only for bidirectional peers
        lines.append("# HELP xlink_peer_rtt_seconds ICMP round-trip time to peer")
        lines.append("# TYPE xlink_peer_rtt_seconds gauge")
        lines.append("# HELP xlink_peer_loss_percent ICMP packet loss to peer")
        lines.append("# TYPE xlink_peer_loss_percent gauge")

        with ping_lock:
            for peer_ip in snapshots:
                result = ping_results.get(peer_ip)
                if not result:
                    continue
                geo = get_geo(peer_ip)
                alias = get_player_alias(peer_ip)
                labels = (f'peer="{peer_ip}",'
                          f'country="{geo["country"]}",'
                          f'city="{geo["city"]}",'
                          f'player="{alias}"')
                lines.append(
                    f'xlink_peer_rtt_seconds{{{labels}}} {result["rtt"]:.6f}'
                )
                lines.append(
                    f'xlink_peer_loss_percent{{{labels}}} {result["loss"]:.1f}'
                )

        # Connection quality score (0-100)
        lines.append("# HELP xlink_connection_score Gaming connection quality 0-100")
        lines.append("# TYPE xlink_connection_score gauge")

        now = time.time()
        for peer_ip, snap in snapshots.items():
            stats = peers.get(peer_ip)
            if not stats:
                continue
            # Skip first 30s (warmup) and last 30s idle (cooldown/disconnect)
            if stats.first_seen > 0 and (now - stats.first_seen) < SCORE_WARMUP:
                continue
            if stats.last_seen > 0 and (now - stats.last_seen) > SCORE_COOLDOWN:
                continue
            geo = get_geo(peer_ip)
            alias = get_player_alias(peer_ip)
            with ping_lock:
                pr = ping_results.get(peer_ip)
            rtt = pr["rtt"] if pr else 0.0
            loss = pr["loss"] if pr else 100.0
            has_icmp = pr is not None and loss < 100.0
            jitter = max(snap["rx_jitter"], snap["tx_jitter"])
            rx_pps = snap["rx_pps"]
            score = connection_score(rtt, jitter, loss, has_icmp, rx_pps)
            labels = (f'peer="{peer_ip}",'
                      f'country="{geo["country"]}",'
                      f'city="{geo["city"]}",'
                      f'player="{alias}"')
            lines.append(
                f'xlink_connection_score{{{labels}}} {score:.1f}'
            )

        body = "\n".join(lines) + "\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, fmt, *args):
        pass


def main():
    local_ips.add(LOCAL_IP)
    _load_player_names()
    print(f"Monitoring {BRIDGE_INTERFACE} for XLink Kai UDP (30000, 34523)")
    print(f"Local IP: {LOCAL_IP}  |  Metrics: http://0.0.0.0:{LISTEN_PORT}/metrics")
    print(f"Player naming UI: http://0.0.0.0:{LISTEN_PORT}/players")

    t = threading.Thread(target=capture, daemon=True)
    t.start()

    p = threading.Thread(target=ping_loop, daemon=True)
    p.start()

    HTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
