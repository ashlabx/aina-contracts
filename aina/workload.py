"""Synthetic incident-triage workload over SIEM and EDR telemetry, with known ground truth.

A case = one host-level investigation request plus the telemetry visible to the backends.
Everything is a deterministic function of (seed, case_id[, scale]) so that independent
service processes regenerate identical data without shipping it over the wire.

Case composition (per seed):
  category ~ {benign_normal .25, benign_admin .15, five malicious categories .12 each}
  4% of requests are invalid (no resolvable host)  -> correct behaviour is to reject.
  Malicious signal strength: strong 60% (4-6 signal records), medium 25% (2-3), weak 15% (1).
  All signal records fall inside the last 24 h; background noise spans 72 h; 30% of noise
  records belong to neighbouring hosts. Noise never matches an indicator by construction,
  so accuracy is independent of telemetry scale.
"""
import random

T0 = 100_000          # "now", in minutes since the workload epoch
DAY = 1440
CATEGORIES = ["benign_normal", "benign_admin", "credential_dumping", "lateral_movement",
              "c2_beaconing", "ransomware_precursor", "data_exfiltration"]
CAT_WEIGHTS = [0.25, 0.15, 0.12, 0.12, 0.12, 0.12, 0.12]
MALICIOUS = set(CATEGORIES[2:])
SIEM_KINDS = {"auth", "flow", "dns"}
EDR_KINDS = {"proc", "proc_access", "file"}
N_HOSTS = 1999

SYSTEM_IMAGES = {"c:\\windows\\system32\\svchost.exe", "c:\\programdata\\microsoft\\windows defender\\msmpeng.exe",
                 "c:\\windows\\system32\\wininit.exe", "c:\\windows\\system32\\csrss.exe"}
COMMON_IPS = ["13.107.42.14", "142.250.72.110", "52.96.165.18", "104.18.32.7", "151.101.1.69",
              "20.190.159.0", "172.217.14.99", "40.126.32.68"]
ALLOWLIST_IPS = set(COMMON_IPS) | {"52.92.17.200", "52.92.17.201"}  # incl. sanctioned backup service
COMMON_DOMAINS = ["outlook.office365.com", "www.google.com", "login.microsoftonline.com", "slack.com",
                  "github.com", "update.microsoft.com", "cdn.jsdelivr.net", "teams.microsoft.com"]
RARE_SUFFIXES = (".duckdns.org", ".ngrok.io", ".top", ".xyz")
FILESHARE_DOMAINS = {"transfer.sh", "file.io", "anonfiles.example"}
NOISE_IMAGES = ["c:\\program files\\google\\chrome\\application\\chrome.exe", "c:\\windows\\explorer.exe",
                "c:\\program files\\microsoft office\\outlook.exe", "c:\\users\\u\\appdata\\local\\teams\\teams.exe",
                "c:\\windows\\system32\\svchost.exe", "c:\\windows\\system32\\notepad.exe"]


def host_name(n):
    return ("SRV-%03d" % n) if (n % 3 == 0 and n < 1000) else ("WS-%04d" % n)


def host_ip(n):
    return "10.20.%d.%d" % (n // 250, n % 250 + 1)


def resolve_ip(ip):
    """Asset inventory lookup: internal IP -> host name (None if unknown)."""
    p = ip.split(".")
    if len(p) != 4 or p[0] != "10" or p[1] != "20":
        return None
    try:
        a, b = int(p[2]), int(p[3])
    except ValueError:
        return None
    n = a * 250 + b - 1
    return host_name(n) if 1 <= n <= N_HOSTS else None


# --------------------------------------------------------------------------------------------
# Indicator catalog: (indicator_id, category, weight). Shared by all backends and reasoners.
# --------------------------------------------------------------------------------------------

def indicators(rec):
    k = rec["kind"]
    out = []
    if k == "proc_access":
        if rec["target_image"].lower().endswith("lsass.exe") and rec["source_image"].lower() not in SYSTEM_IMAGES:
            out.append(("I_LSASS_ACCESS", "credential_dumping", 3.0))
    elif k == "proc":
        cmd = rec["cmdline"].lower()
        img = rec["image"].lower()
        if "lsass" in cmd and ("procdump" in cmd or "minidump" in cmd or "sekurlsa" in cmd):
            out.append(("I_CRED_DUMP_CMD", "credential_dumping", 3.0))
        if img.endswith("psexec.exe") or img.endswith("psexesvc.exe"):
            out.append(("I_PSEXEC", "lateral_movement", 1.5))
        if "wmic" in cmd and "/node:" in cmd:
            out.append(("I_WMIC_REMOTE", "lateral_movement", 2.0))
        if "vssadmin" in cmd and "delete shadows" in cmd:
            out.append(("I_VSS_DELETE", "ransomware_precursor", 3.0))
        if "bcdedit" in cmd and "recoveryenabled no" in cmd:
            out.append(("I_BCDEDIT", "ransomware_precursor", 2.0))
        if (img.endswith("7z.exe") or img.endswith("rar.exe")) and " -p" in cmd:
            out.append(("I_ARCHIVE_PW", "data_exfiltration", 1.5))
    elif k == "file":
        if rec["op"] == "rename" and rec["path"].endswith(".locked"):
            out.append(("I_RANSOM_EXT", "ransomware_precursor", 1.0))
    elif k == "auth":
        if rec["logon_type"] == 3 and rec["src_host"] == rec["host"] and rec["dst_host"] != rec["host"]:
            out.append(("I_REMOTE_LOGON", "lateral_movement", 0.75))
    elif k == "flow":
        if not rec["dst_ip"].startswith("10.") and rec["dst_ip"] not in ALLOWLIST_IPS:
            if rec["bytes_out"] > 50_000_000:
                out.append(("I_BIG_UPLOAD", "data_exfiltration", 2.5))
            elif rec["dst_port"] == 443:
                out.append(("I_RARE_DEST", "c2_beaconing", 0.5))
    elif k == "dns":
        q = rec["qname"]
        if q.endswith(RARE_SUFFIXES):
            out.append(("I_RARE_DNS", "c2_beaconing", 1.5))
        if q in FILESHARE_DOMAINS:
            out.append(("I_FILESHARE_DNS", "data_exfiltration", 1.0))
    return out


INDICATOR_WEIGHT = {"I_LSASS_ACCESS": 3.0, "I_CRED_DUMP_CMD": 3.0, "I_PSEXEC": 1.5, "I_WMIC_REMOTE": 2.0,
                    "I_VSS_DELETE": 3.0, "I_BCDEDIT": 2.0, "I_ARCHIVE_PW": 1.5, "I_RANSOM_EXT": 1.0,
                    "I_REMOTE_LOGON": 0.75, "I_BIG_UPLOAD": 2.5, "I_RARE_DEST": 0.5, "I_RARE_DNS": 1.5,
                    "I_FILESHARE_DNS": 1.0}


# --------------------------------------------------------------------------------------------
# Requests
# --------------------------------------------------------------------------------------------

WINDOW_PHRASES = [("last 24 hours", 1440, .35), ("past 24h", 1440, .10), ("last day", 1440, .10),
                  ("since yesterday", 1440, .15), ("last 2 days", 2880, .15), ("past 48 hours", 2880, .10),
                  ("last 3 days", 4320, .05)]
TEMPLATES = ["Investigate host {h} for suspicious activity over the {w}.",
             "Triage {h}: anything malicious in the {w}?",
             "Check {h} for signs of compromise during the {w}.",
             "Was {h} compromised in the {w}?"]
INVALID_TEMPLATES = ["Investigate the server for suspicious activity over the {w}.",
                     "Check for signs of compromise during the {w}.",
                     "Anything malicious on the finance laptop in the {w}?"]


def _render_host(rng, n):
    h = host_name(n)
    r = rng.random()
    if r < .55:
        return h
    if r < .70:
        return h.lower()
    if r < .85:
        return h.lower() + ".corp.example"
    return host_ip(n)


def render_request(rng, n, invalid):
    phrases = [p for p, _, _ in WINDOW_PHRASES]
    weights = [w for _, _, w in WINDOW_PHRASES]
    i = rng.choices(range(len(phrases)), weights)[0]
    w = phrases[i]
    if invalid:
        text = rng.choice(INVALID_TEMPLATES).format(w=w)
    else:
        text = rng.choice(TEMPLATES).format(h=_render_host(rng, n), w=w)
    high = rng.random() < 0.20
    if high:
        text += " High confidence required."
    return text, (0.8 if high else 0.6)


# --------------------------------------------------------------------------------------------
# Signal planting
# --------------------------------------------------------------------------------------------

def _ts(rng):
    return rng.randint(T0 - DAY + 10, T0 - 5)


def _ext_ip(rng):
    return "%d.%d.%d.%d" % (rng.choice([45, 91, 185, 193, 203]), rng.randint(1, 254), rng.randint(1, 254), rng.randint(1, 254))


def _other_host(rng, n):
    m = n
    while m == n:
        m = rng.randint(1, N_HOSTS)
    return host_name(m)


def _signal_templates(cat, rng, host, n):
    """Return a list of zero-arg callables, each producing one signal record for `cat`."""
    U = "user%d" % rng.randint(1, 500)
    if cat == "credential_dumping":
        return [
            lambda: dict(kind="proc_access", source_image="c:\\users\\public\\svc%d.exe" % rng.randint(1, 99),
                         target_image="c:\\windows\\system32\\lsass.exe", access_mask="0x1010", user=U),
            lambda: dict(kind="proc", image="c:\\tools\\procdump.exe", parent="c:\\windows\\system32\\cmd.exe",
                         cmdline="procdump.exe -ma lsass.exe c:\\temp\\l.dmp", user=U),
            lambda: dict(kind="proc", image="c:\\windows\\system32\\rundll32.exe", parent="c:\\windows\\system32\\cmd.exe",
                         cmdline="rundll32.exe comsvcs.dll, MiniDump 624 c:\\temp\\lsass.dmp full", user=U),
        ]
    if cat == "lateral_movement":
        return [
            lambda: dict(kind="proc", image="c:\\tools\\psexec.exe", parent="c:\\windows\\system32\\cmd.exe",
                         cmdline="psexec.exe \\\\%s -s cmd.exe" % _other_host(rng, n), user=U),
            lambda: dict(kind="proc", image="c:\\windows\\system32\\wbem\\wmic.exe", parent="c:\\windows\\system32\\cmd.exe",
                         cmdline="wmic /node:%s process call create c:\\temp\\a.exe" % _other_host(rng, n), user=U),
            lambda: dict(kind="auth", user=U, src_host=host, dst_host=_other_host(rng, n), logon_type=3, result="success"),
            lambda: dict(kind="auth", user=U, src_host=host, dst_host=_other_host(rng, n), logon_type=3, result="success"),
        ]
    if cat == "c2_beaconing":
        dst = _ext_ip(rng)
        q = "%s%s" % ("".join(rng.choice("abcdefghijkmnpqrstuvwxyz234567") for _ in range(8)), rng.choice(RARE_SUFFIXES))
        return [
            lambda: dict(kind="flow", dst_ip=dst, dst_port=443, bytes_out=rng.randint(300, 2000), bytes_in=rng.randint(300, 4000), proto="tcp"),
            lambda: dict(kind="dns", qname=q, rtype="A"),
        ]
    if cat == "ransomware_precursor":
        return [
            lambda: dict(kind="proc", image="c:\\windows\\system32\\vssadmin.exe", parent="c:\\users\\public\\enc.exe",
                         cmdline="vssadmin.exe delete shadows /all /quiet", user=U),
            lambda: dict(kind="proc", image="c:\\windows\\system32\\bcdedit.exe", parent="c:\\users\\public\\enc.exe",
                         cmdline="bcdedit /set {default} recoveryenabled no", user=U),
            lambda: dict(kind="file", path="c:\\users\\%s\\documents\\f%d.docx.locked" % (U, rng.randint(1, 999)), op="rename", user=U),
        ]
    if cat == "data_exfiltration":
        return [
            lambda: dict(kind="flow", dst_ip=_ext_ip(rng), dst_port=443, bytes_out=rng.randint(80, 400) * 1_000_000,
                         bytes_in=rng.randint(1000, 9000), proto="tcp"),
            lambda: dict(kind="proc", image="c:\\program files\\7-zip\\7z.exe", parent="c:\\windows\\explorer.exe",
                         cmdline="7z.exe a -pS3cret c:\\temp\\q.7z c:\\finance", user=U),
            lambda: dict(kind="dns", qname=rng.choice(sorted(FILESHARE_DOMAINS)), rtype="A"),
        ]
    raise ValueError(cat)


def plant_signals(rng, cat, host, n):
    sig = []
    if cat in MALICIOUS:
        r = rng.random()
        k = rng.randint(4, 6) if r < .60 else (rng.randint(2, 3) if r < .85 else 1)
        tpl = _signal_templates(cat, rng, host, n)
        if cat == "c2_beaconing":
            # beacon: k+2 flows on a near-regular period, plus DNS lookups
            period = rng.randint(30, 90)
            start = T0 - DAY + rng.randint(30, 300)
            for j in range(k + 2 if k > 1 else 1):
                rec = tpl[0]()
                rec["ts"] = start + j * period + rng.randint(-2, 2)
                sig.append(rec)
            if k >= 2:
                rec = tpl[1]()
                rec["ts"] = start - 1
                sig.append(rec)
        else:
            for _ in range(k):
                rec = rng.choice(tpl)()
                rec["ts"] = _ts(rng)
                sig.append(rec)
    elif cat == "benign_admin":
        A = "adm-%s" % rng.choice(["jlee", "mrao", "kchen", "spatel"])
        sig.append(dict(kind="proc", image="c:\\tools\\psexec.exe", parent="c:\\windows\\system32\\cmd.exe",
                        cmdline="psexec.exe \\\\%s -s ipconfig /all" % _other_host(rng, n), user=A, ts=_ts(rng)))
        for _ in range(rng.randint(1, 2)):
            sig.append(dict(kind="auth", user=A, src_host=host, dst_host=_other_host(rng, n), logon_type=3, result="success", ts=_ts(rng)))
        sig.append(dict(kind="proc", image="c:\\windows\\system32\\vssadmin.exe", parent="c:\\program files\\backup\\agent.exe",
                        cmdline="vssadmin.exe list shadows", user="SYSTEM", ts=_ts(rng)))
        sig.append(dict(kind="flow", dst_ip="52.92.17.200", dst_port=443, bytes_out=rng.randint(100, 900) * 1_000_000,
                        bytes_in=20000, proto="tcp", ts=_ts(rng)))
        sig.append(dict(kind="proc_access", source_image="c:\\programdata\\microsoft\\windows defender\\msmpeng.exe",
                        target_image="c:\\windows\\system32\\lsass.exe", access_mask="0x1000", user="SYSTEM", ts=_ts(rng)))
    else:  # benign_normal: occasionally one weak, isolated indicator (e.g. a single odd DNS lookup)
        if rng.random() < 0.30:
            q = "%s%s" % ("".join(rng.choice("abcdefghijkmnpqrstuvwxyz") for _ in range(7)), rng.choice(RARE_SUFFIXES))
            sig.append(dict(kind="dns", qname=q, rtype="A", ts=_ts(rng)))
    for s in sig:
        s["host"] = host
    return sig


def make_case(seed, case_id):
    rng = random.Random("case:%s:%s" % (seed, case_id))
    cat = rng.choices(CATEGORIES, CAT_WEIGHTS)[0]
    n = rng.randint(1, N_HOSTS)
    host = host_name(n)
    invalid = rng.random() < 0.04
    request, target = render_request(rng, n, invalid)
    signals = plant_signals(rng, cat, host, n)
    if invalid:
        expected = {"verdict": "invalid", "category": None}
    else:
        expected = {"verdict": "malicious" if cat in MALICIOUS else "benign",
                    "category": cat if cat in MALICIOUS else "benign"}
    return {"seed": seed, "case_id": case_id, "category": cat, "host": host, "host_n": n, "request": request,
            "target_confidence": target, "invalid": invalid, "expected": expected, "signals": signals}


# --------------------------------------------------------------------------------------------
# Background telemetry
# --------------------------------------------------------------------------------------------

def _noise_record(rng, host, n):
    k = rng.choices(["auth", "flow", "dns", "proc", "proc_access", "file"], [.15, .30, .20, .25, .02, .08])[0]
    ts = rng.randint(T0 - 3 * DAY, T0)
    U = "user%d" % rng.randint(1, 500)
    if k == "auth":
        # interactive logons, or inbound network logons (not outbound lateral movement)
        if rng.random() < .6:
            r = dict(kind="auth", user=U, src_host=host, dst_host=host, logon_type=rng.choice([2, 10]), result="success")
        else:
            r = dict(kind="auth", user=U, src_host=_other_host(rng, n), dst_host=host, logon_type=3,
                     result=rng.choice(["success", "success", "failure"]))
    elif k == "flow":
        r = dict(kind="flow", dst_ip=rng.choice(COMMON_IPS) if rng.random() < .8 else "10.20.%d.%d" % (rng.randint(0, 7), rng.randint(1, 250)),
                 dst_port=rng.choice([443, 443, 80, 53, 445]), bytes_out=rng.randint(200, 2_000_000),
                 bytes_in=rng.randint(200, 9_000_000), proto="tcp")
    elif k == "dns":
        r = dict(kind="dns", qname=rng.choice(COMMON_DOMAINS), rtype=rng.choice(["A", "AAAA"]))
    elif k == "proc":
        img = rng.choice(NOISE_IMAGES)
        r = dict(kind="proc", image=img, parent="c:\\windows\\explorer.exe", cmdline=img.split("\\")[-1] + " --type=renderer", user=U)
    elif k == "proc_access":
        r = dict(kind="proc_access", source_image="c:\\programdata\\microsoft\\windows defender\\msmpeng.exe",
                 target_image=rng.choice(["c:\\windows\\system32\\lsass.exe", "c:\\windows\\explorer.exe"]),
                 access_mask="0x1000", user="SYSTEM")
    else:
        r = dict(kind="file", path="c:\\users\\%s\\documents\\report%d.docx" % (U, rng.randint(1, 999)),
                 op=rng.choice(["create", "write", "rename"]), user=U)
    r["ts"] = ts
    r["host"] = host
    return r


def case_records(case, scale):
    """All telemetry for a case at a given scale (records per case). Returns {'siem': [...], 'edr': [...]}."""
    rng = random.Random("noise:%s:%s:%s" % (case["seed"], case["case_id"], scale))
    n_noise = max(0, scale - len(case["signals"]))
    recs = []
    for _ in range(n_noise):
        if rng.random() < 0.30:
            m = rng.randint(1, N_HOSTS)
            recs.append(_noise_record(rng, host_name(m), m))
        else:
            recs.append(_noise_record(rng, case["host"], case["host_n"]))
    recs.extend(dict(s) for s in case["signals"])
    recs.sort(key=lambda r: (r["ts"], r["kind"]))
    out = {"siem": [], "edr": []}
    for i, r in enumerate(recs):
        r["rid"] = "r%06d" % i
        out["siem" if r["kind"] in SIEM_KINDS else "edr"].append(r)
    return out
