#!/usr/bin/env python3
"""
Sentinel Lake - log normalizer (Phase 1)
Reads raw security logs from multiple sources (SSH auth, sudo, UFW firewall)
and maps every event into one common OCSF-style schema, so different formats
become a single consistent shape an analyst can query and correlate.
"""
import re, json, argparse
from datetime import datetime

SSH_RE = re.compile(
    r'(?P<ts>\w{3}\s+\d+\s[\d:]+)\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+'
    r'(?P<result>Failed|Accepted)\s+password\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+'
    r'from\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<port>\d+)'
)
SUDO_RE = re.compile(
    r'(?P<ts>\w{3}\s+\d+\s[\d:]+)\s+(?P<host>\S+)\s+sudo:\s+(?P<user>\S+)\s+:.*?'
    r'USER=(?P<target>\S+)\s+;\s+COMMAND=(?P<cmd>.+)'
)
UFW_RE = re.compile(
    r'(?P<ts>\w{3}\s+\d+\s[\d:]+)\s+(?P<host>\S+)\s+kernel:.*?\[UFW BLOCK\].*?'
    r'SRC=(?P<src_ip>\S+)\s+DST=(?P<dst_ip>\S+).*?PROTO=(?P<proto>\S+)\s+'
    r'SPT=(?P<spt>\d+)\s+DPT=(?P<dpt>\d+)'
)

def iso(ts):
    try:
        return datetime.strptime(f"{datetime.now().year} {ts}", "%Y %b %d %H:%M:%S").isoformat()
    except ValueError:
        return ts

def normalize(line):
    line = line.strip()
    if not line:
        return None

    m = SSH_RE.search(line)
    if m:
        failed = m.group("result") == "Failed"
        return {
            "class_name": "Authentication", "class_uid": 3002, "activity": "Logon",
            "time": iso(m.group("ts")),
            "status": "Failure" if failed else "Success",
            "status_id": 2 if failed else 1,
            "severity": "Medium" if failed else "Informational",
            "src_endpoint": {"ip": m.group("src_ip"), "port": int(m.group("port"))},
            "actor": {"user": {"name": m.group("user")}},
            "dst_endpoint": {"hostname": m.group("host")},
            "metadata": {"product": "sshd", "log_source": "linux_auth"},
            "raw_event": line,
        }

    m = SUDO_RE.search(line)
    if m:
        return {
            "class_name": "Authentication", "class_uid": 3002, "activity": "Privilege Escalation",
            "time": iso(m.group("ts")), "status": "Success", "status_id": 1,
            "severity": "Informational",
            "actor": {"user": {"name": m.group("user")}},
            "target_user": m.group("target"), "command": m.group("cmd"),
            "dst_endpoint": {"hostname": m.group("host")},
            "metadata": {"product": "sudo", "log_source": "linux_auth"},
            "raw_event": line,
        }

    m = UFW_RE.search(line)
    if m:
        return {
            "class_name": "Network Activity", "class_uid": 4001, "activity": "Denied",
            "time": iso(m.group("ts")), "status": "Blocked", "status_id": 2,
            "severity": "Medium",
            "src_endpoint": {"ip": m.group("src_ip"), "port": int(m.group("spt"))},
            "dst_endpoint": {"ip": m.group("dst_ip"), "port": int(m.group("dpt")),
                             "hostname": m.group("host")},
            "connection_info": {"protocol": m.group("proto")},
            "metadata": {"product": "ufw", "log_source": "linux_firewall"},
            "raw_event": line,
        }

    return {"class_name": "Unmapped", "raw_event": line}

def detect(events, threshold):
    print("=== DETECTIONS ===")

    auth_fails = {}
    for e in events:
        if e.get("class_name") == "Authentication" and e.get("status") == "Failure":
            ip = e["src_endpoint"]["ip"]
            auth_fails[ip] = auth_fails.get(ip, 0) + 1
    print("[SSH brute force]")
    bf = {ip: n for ip, n in auth_fails.items() if n >= threshold}
    for ip, n in bf.items():
        print(f"  ALERT  {ip} -> {n} failed logins (>= {threshold})")
    if not bf:
        print("  none")

    fw_blocks = {}
    for e in events:
        if e.get("class_name") == "Network Activity" and e.get("status") == "Blocked":
            ip = e["src_endpoint"]["ip"]
            fw_blocks[ip] = fw_blocks.get(ip, 0) + 1
    print("[Firewall blocks]")
    for ip, n in fw_blocks.items():
        print(f"  {ip} -> {n} blocked connections")

    both = set(auth_fails) & set(fw_blocks)
    print("[Correlation: same IP in auth failures AND firewall blocks]")
    if both:
        for ip in both:
            print(f"  HIGH CONFIDENCE  {ip}: {auth_fails[ip]} failed logins + {fw_blocks[ip]} firewall blocks")
    else:
        print("  none")
    print()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logfiles", nargs="+", help="one or more raw log files")
    ap.add_argument("--detect", action="store_true")
    ap.add_argument("--threshold", type=int, default=3)
    args = ap.parse_args()

    events = []
    for path in args.logfiles:
        with open(path) as f:
            for line in f:
                ev = normalize(line)
                if ev:
                    events.append(ev)

    if args.detect:
        detect(events, args.threshold)

    for e in events:
        print(json.dumps(e))

if __name__ == "__main__":
    main()
