import re
import sys
import json
import argparse
import logging
import requests
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
# test
log = logging.getLogger("cti_scorer")


ENFORCE_THRESHOLD = 0.58
TTL_INBOUND_SECONDS = 72 * 3600    # 72 h
TTL_OUTBOUND_SECONDS = 24 * 3600    # 24 h
REQUEST_TIMEOUT = 10

ABUSECH_API_KEY = "7743f521c1d27db1a329fb6555c15947580ea8ec94d4b822"

ML_MODEL_DIR = "/home/sakila/Desktop/Codes/models/models"
ML_FEATURE_FILE = "/home/sakila/Desktop/Codes/models/data/data/feature_columns.json"

REQUEST_HEADERS = {"User-Agent": "SOHO-CTI-Engine/1.0"}

URLHAUS_HEADERS = {
    "User-Agent": "SOHO-CTI-Engine/1.0",
    "Auth-Key":   ABUSECH_API_KEY,
}

THREATFOX_HEADERS = {
    "User-Agent":   "SOHO-CTI-Engine/1.0",
    "Auth-Key":     ABUSECH_API_KEY,
    "Content-Type": "application/json",
}

CATEGORY_WEIGHTS = {
    "botnet":     1.0,
    "c2":         1.0,
    "ransomware": 0.9,
    "malware":    0.85,
    "phishing":   0.75,
    "spam":       0.5,
    "apt":        0.2,
    "unknown":    0.3,
}

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


@dataclass
class APIRecord:
    found:      bool = False
    source:     str = ""
    tags:       list = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen:  Optional[str] = None
    confidence: float = 0.0
    raw:        dict = field(default_factory=dict)


@dataclass
class ScoringComponents:
    category_weight:     float = 0.0
    corroboration_score: float = 0.0
    freshness_score:     float = 0.0
    rule_score:          float = 0.0

    ml_score:            float = 0.0
    ml_used:             bool = False
    ml_confidence:       str = ""
    ml_model_agreement:  float = 0.0


@dataclass
class CTIResult:
    value:          str = ""
    ioc_type:       str = ""

    urlhaus_record: APIRecord = field(default_factory=APIRecord)
    abusech_record: APIRecord = field(default_factory=APIRecord)
    feeds_found:    int = 0
    combined_tags:  list = field(default_factory=list)
    first_seen:     Optional[str] = None
    age_days:       float = 9999.0

    components:     ScoringComponents = field(
        default_factory=ScoringComponents)

    ml_details:     dict = field(default_factory=dict)

    final_score:    float = 0.0
    decision:       str = "DISCARD"
    threshold:      float = ENFORCE_THRESHOLD
    ttl_seconds:    int = 0
    ipset_target:   str = ""

    score_source:   str = ""
    error:          Optional[str] = None


def _category_weight(tags: list) -> tuple[float, str]:
    best_w, best_cat = CATEGORY_WEIGHTS["unknown"], "unknown"
    joined = " ".join(tags).lower()
    for cat, w in sorted(CATEGORY_WEIGHTS.items(), key=lambda x: -x[1]):
        if cat in joined:
            return w, cat
    return best_w, best_cat


def _corroboration_score(feeds_found: int) -> float:
    """
    4+ feeds → 1.0
    2-3 feeds → 0.8
    1 feed    → 0.6
    0 feeds   → 0.0  (triggers ML fallback)
    """
    if feeds_found >= 4:
        return 1.0
    if feeds_found >= 2:
        return 0.8
    if feeds_found == 1:
        return 0.6
    return 0.0


def _freshness_score(first_seen_str: Optional[str]) -> tuple[float, float]:
    """
    < 7 days  → 1.0
    < 30 days → 0.7
    < 90 days → 0.5
    ≥ 90 days → 0.1
    Returns (score, age_days).
    """
    if not first_seen_str:
        return 0.5, 9999.0

    try:
        s = first_seen_str.strip()
        if s.endswith(" UTC"):
            s = s[:-4]

        dt = None
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
        ):
            try:
                dt = datetime.strptime(s[:len(fmt)], fmt)
                break
            except ValueError:
                continue

        if dt is None:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        delta = datetime.now(timezone.utc) - dt
        age_days = delta.total_seconds() / 86400

        if age_days < 7:
            return 1.0, age_days
        if age_days < 30:
            return 0.7, age_days
        if age_days < 90:
            return 0.5, age_days
        return 0.1, age_days

    except Exception:
        return 0.5, 9999.0


def _compute_rule_score(
    tags: list,
    feeds_found: int,
    first_seen: Optional[str],
) -> tuple[ScoringComponents, float]:
    cat_w, _ = _category_weight(tags)
    corr_s = _corroboration_score(feeds_found)
    fresh_s, age_days = _freshness_score(first_seen)
    rule_score = round(cat_w * corr_s * fresh_s, 4)

    comp = ScoringComponents(
        category_weight=cat_w,
        corroboration_score=corr_s,
        freshness_score=fresh_s,
        rule_score=rule_score+0.5,
    )
    return comp, age_days


def _normalise(value: str) -> tuple[str, str]:
    v = value.strip()
    v = re.sub(r"^https?://", "", v)
    v = v.split("/")[0].split("?")[0].split(":")[0]
    v = v.lower()
    ioc_type = "ip" if _IP_RE.match(v) else "domain"
    return v, ioc_type


def _query_urlhaus(value: str, ioc_type: str) -> APIRecord:

    record = APIRecord(source="urlhaus")
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": value},
            headers=URLHAUS_HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        body = resp.json()

        status = body.get("query_status", "")

        if status == "unauthorized":
            log.error(
                "[URLhaus] Auth-Key rejected — check ABUSECH_API_KEY constant.")
            record.found = False
            return record

        if status == "no_results":
            record.found = False
            return record

        if status != "is_host":
            log.warning(
                f"[URLhaus] Unexpected query_status '{status}' for {value}")
            record.found = False
            return record

        urls = body.get("urls") or []
        if not urls:
            record.found = False
            return record

        record.found = True
        record.raw = body

        tags, dates = set(), []
        for entry in urls:
            for tag in (entry.get("tags") or []):
                tags.add(tag.lower())
            if entry.get("date_added"):
                dates.append(entry["date_added"])
            sig = (entry.get("payload") or {}).get("signature") or ""
            if sig:
                tags.add(sig.lower())

        record.tags = sorted(tags)
        record.first_seen = min(dates) if dates else None
        record.last_seen = max(dates) if dates else None
        record.confidence = min(len(urls) / 10.0, 1.0)

    except requests.exceptions.Timeout:
        log.warning(f"[URLhaus] Timeout for {value}")
    except requests.exceptions.RequestException as e:
        log.warning(f"[URLhaus] Request error for {value}: {e}")
    except Exception as e:
        log.warning(f"[URLhaus] Unexpected error for {value}: {e}")

    return record


def _query_threatfox(value: str) -> APIRecord:

    record = APIRecord(source="abuse.ch/threatfox")
    try:
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": value},
            headers=THREATFOX_HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        status = data.get("query_status", "")

        if status == "no_result":
            record.found = False
            return record

        if status == "unauthorized":
            log.error(
                "[ThreatFox] Auth-Key rejected — check ABUSECH_API_KEY constant.")
            record.found = False
            return record

        if status == "illegal_search_term":
            log.warning(f"[ThreatFox] Illegal search term: {value}")
            record.found = False
            return record

        if status != "ok":
            log.warning(
                f"[ThreatFox] Unexpected query_status '{status}' for {value}")
            record.found = False
            return record

        iocs = data.get("data") or []
        if not iocs:
            record.found = False
            return record

        record.found = True
        record.raw = data

        tags, dates, confidences = set(), [], []
        for ioc in iocs:
            threat_type = (ioc.get("threat_type") or "").lower()
            malware = (ioc.get("malware") or "").lower()
            if threat_type:
                tags.add(threat_type)
            if malware:
                tags.add(malware)

            fs = (ioc.get("first_seen") or "").strip()
            if fs:
                if fs.endswith(" UTC"):
                    fs = fs[:-4]
                dates.append(fs)

            ls = (ioc.get("last_seen") or "").strip()
            if ls and ls.endswith(" UTC"):
                ls = ls[:-4]

            cl = ioc.get("confidence_level")
            if cl is not None:
                confidences.append(int(cl) / 100.0)

        record.tags = sorted(t for t in tags if t)
        record.first_seen = min(dates) if dates else None
        record.last_seen = max(dates) if dates else None
        record.confidence = min(
            sum(confidences) / len(confidences) if confidences else 0.5,
            1.0,
        )

    except requests.exceptions.Timeout:
        log.warning(f"[ThreatFox] Timeout for {value}")
    except requests.exceptions.RequestException as e:
        log.warning(f"[ThreatFox] Request error for {value}: {e}")
    except Exception as e:
        log.warning(f"[ThreatFox] Unexpected error for {value}: {e}")

    return record


def _query_feodo_ip(ip: str) -> APIRecord:

    record = APIRecord(source="abuse.ch/feodo")
    try:
        resp = requests.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            headers=REQUEST_HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        entries = resp.json()

        for entry in entries:
            if entry.get("ip_address", "").strip() == ip:
                malware = (entry.get("malware") or "unknown").lower()
                record.found = True
                record.tags = ["botnet", "c2", malware]
                record.first_seen = entry.get("first_seen")
                record.last_seen = entry.get("last_online")
                record.confidence = 0.95
                record.raw = entry
                break

    except requests.exceptions.Timeout:
        log.warning(f"[Feodo] Timeout for {ip}")
    except Exception as e:
        log.warning(f"[Feodo] Error for {ip}: {e}")

    return record


def _query_abusech(value: str, ioc_type: str) -> APIRecord:

    if ioc_type == "ip":
        tf_record = _query_threatfox(value)
        if tf_record.found:
            return tf_record
        log.debug(f"[abuse.ch] ThreatFox miss for IP {value} — trying Feodo")
        return _query_feodo_ip(value)
    else:
        return _query_threatfox(value)


_ml_model = None


def _get_ml_model():

    global _ml_model
    if _ml_model is None:
        try:
            from predictor import URLPredictor
            _ml_model = URLPredictor(
                model_dir=ML_MODEL_DIR,
                feature_file=ML_FEATURE_FILE,
            )
            log.info("[ML] URLPredictor loaded for fallback.")
        except Exception as e:
            log.warning(f"[ML] Could not load URLPredictor: {e}")
            _ml_model = False
    return _ml_model if _ml_model else None


def _ml_fallback(value: str, ioc_type: str) -> tuple[float, str, dict]:
    model = _get_ml_model()
    if model is None:
        return 0.0, "ml_unavailable", {}

    try:
        result = model.predict(value, return_details=True)
        ml_score = float(result.get("probability", 0.0))
        return round(ml_score, 4), "url_predictor", result
    except Exception as e:
        log.warning(f"[ML fallback] Error scoring {value}: {e}")
        return 0.0, f"ml_error: {e}", {}


def score(value: str) -> CTIResult:

    result = CTIResult()
    result.value = value
    clean, ioc_type = _normalise(value)
    result.ioc_type = ioc_type

    log.debug(f"[score] Querying APIs for {clean} ({ioc_type}) ...")

    urlhaus_rec = _query_urlhaus(clean, ioc_type)
    abusech_rec = _query_abusech(clean, ioc_type)

    result.urlhaus_record = urlhaus_rec
    result.abusech_record = abusech_rec

    feeds_found = sum([urlhaus_rec.found, abusech_rec.found])
    result.feeds_found = feeds_found

    all_tags = list(set(urlhaus_rec.tags + abusech_rec.tags))
    result.combined_tags = all_tags

    dates = [d for d in [urlhaus_rec.first_seen, abusech_rec.first_seen] if d]
    first_seen = min(dates) if dates else None
    result.first_seen = first_seen

    if feeds_found > 0:
        comp, age_days = _compute_rule_score(all_tags, feeds_found, first_seen)
        result.age_days = age_days
        result.components = comp
        result.final_score = comp.rule_score
        result.score_source = "api"

    else:
        log.debug(f"[score] No API record for {clean} — using ML fallback")

        ml_score, ml_source, ml_detail = _ml_fallback(clean, ioc_type)

        comp = ScoringComponents(
            ml_score=ml_score,
            ml_used=True,
            ml_confidence=ml_detail.get("confidence", ""),
            ml_model_agreement=ml_detail.get("model_agreement", 0.0),
        )

        result.age_days = 9999.0
        result.components = comp
        result.ml_details = ml_detail
        result.final_score = ml_score
        result.score_source = f"ml_fallback ({ml_source})"

    result.final_score = round(result.final_score, 4)
    result.threshold = ENFORCE_THRESHOLD

    if result.final_score >= ENFORCE_THRESHOLD:
        result.decision = "ENFORCE"
        result.ipset_target = "CTI_BLOCK_INBOUND"
        result.ttl_seconds = TTL_INBOUND_SECONDS
    else:
        result.decision = "DISCARD"
        result.ipset_target = ""
        result.ttl_seconds = 0

    return result


def _fmt_plain(r: CTIResult) -> str:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    DIM = "\033[2m"

    dec_color = RED if r.decision == "ENFORCE" else GREEN
    score_color = RED if r.final_score >= 0.6 else \
        YELLOW if r.final_score >= 0.4 else GREEN

    lines = [
        "",
        f"{BOLD}{'─'*52}{RESET}",
        f"{BOLD}  CTI Score Result{RESET}",
        f"{'─'*52}",
        f"  IOC Value    : {BOLD}{r.value}{RESET}",
        f"  Type         : {r.ioc_type}",
        f"  Clean Value  : {_normalise(r.value)[0]}",
        "",
        f"  {BOLD}API Findings{RESET}",
        f"  URLhaus      : {'✓ FOUND' if r.urlhaus_record.found else '✗ not listed'}",
        f"  Abuse.ch     : {'✓ FOUND' if r.abusech_record.found else '✗ not listed'}",
        f"  Feeds Found  : {r.feeds_found}",
        f"  Combined Tags: {', '.join(r.combined_tags) if r.combined_tags else '—'}",
        f"  First Seen   : {r.first_seen or 'unknown'}",
        f"  Age          : {f'{r.age_days:.1f} days' if r.age_days <
                            9000 else 'unknown'}",
        "",
        f"  {BOLD}Scoring Components{RESET}  ({r.score_source})",
    ]

    if r.components.ml_used:
        conf_color = (
            RED if r.components.ml_confidence == "HIGH" else
            YELLOW if r.components.ml_confidence == "MEDIUM" else
            GREEN
        )
        agree_pct = int(r.components.ml_model_agreement * 100)

        lines += [
            f"  {DIM}Category wt  : — (no API record){RESET}",
            f"  {DIM}Corroboration: — (no API record){RESET}",
            f"  {DIM}Freshness    : — (no API record){RESET}",
            f"  ML Score     : {score_color}{BOLD}{r.components.ml_score:.4f}{RESET}  "
            f"{DIM}(URLPredictor ensemble){RESET}",
            f"  ML Confidence: {conf_color}{r.components.ml_confidence or '—'}{RESET}",
            f"  Model Agree  : {agree_pct}%  "
            f"{DIM}(sub-models in agreement){RESET}",
        ]

        model_scores = r.ml_details.get("model_scores", {})
        if model_scores:
            lines.append(f"  {DIM}Per-model scores:{RESET}")
            for mname, mscore in sorted(model_scores.items(),
                                        key=lambda x: -x[1]):
                bar_fill = int(mscore * 20)
                bar = "█" * bar_fill + "░" * (20 - bar_fill)
                m_color = RED if mscore >= 0.6 else YELLOW if mscore >= 0.4 else GREEN
                lines.append(
                    f"    {mname:<20} {m_color}{mscore:.4f}{RESET}  "
                    f"{DIM}[{bar}]{RESET}"
                )
    else:
        lines += [
            f"  Category wt  : {r.components.category_weight:.2f}  "
            f"{DIM}({', '.join(r.combined_tags[:2]) or 'unknown'}){RESET}",
            f"  Corroboration: {r.components.corroboration_score:.2f}  "
            f"{DIM}({r.feeds_found} feed{'s' if r.feeds_found != 1 else ''}){RESET}",
            f"  Freshness    : {r.components.freshness_score:.2f}  "
            f"{DIM}(age: {f'{r.age_days:.1f}d' if r.age_days <
                          9000 else 'unknown'}){RESET}",
            f"  Rule Score   : {r.components.category_weight:.2f} × "
            f"{r.components.corroboration_score:.2f} × "
            f"{r.components.freshness_score:.2f} = "
            f"{BOLD}{r.components.rule_score:.4f}{RESET}",
        ]

    lines += [
        "",
        f"  {'─'*48}",
        f"  Final Score  : {score_color}{BOLD}{r.final_score:.4f}{RESET}"
        f"  (threshold: {r.threshold})",
        f"  Decision     : {dec_color}{BOLD}{r.decision}{RESET}",
    ]

    if r.decision == "ENFORCE":
        lines += [
            f"  ipset Target : {r.ipset_target}",
            f"  TTL          : {r.ttl_seconds // 3600}h ({r.ttl_seconds}s)",
        ]

    lines += [f"{'─'*52}", ""]
    return "\n".join(lines)


def _fmt_verbose(r: CTIResult) -> str:
    base = _fmt_plain(r)
    extras = []

    if r.urlhaus_record.found and r.urlhaus_record.raw:
        extras.append("\n  [URLhaus Raw]")
        for k, v in list(r.urlhaus_record.raw.items())[:6]:
            extras.append(f"    {k}: {v}")

    if r.abusech_record.found and r.abusech_record.raw:
        extras.append("\n  [Abuse.ch Raw]")
        raw = r.abusech_record.raw
        data_items = raw.get("data", [raw])
        if isinstance(data_items, list) and data_items:
            for k, v in list(data_items[0].items())[:8]:
                extras.append(f"    {k}: {v}")

    if r.components.ml_used and r.ml_details:
        extras.append("\n  [URLPredictor Full Detail]")
        skip = {"model_scores", "meta_weights"}
        for k, v in r.ml_details.items():
            if k not in skip:
                extras.append(f"    {k}: {v}")
        if "meta_weights" in r.ml_details:
            extras.append("    meta_weights:")
            for mname, mw in r.ml_details["meta_weights"].items():
                extras.append(f"      {mname}: {mw:.4f}")

    return base + "\n".join(extras)


def _fmt_json(r: CTIResult) -> str:
    out = {
        "value":         r.value,
        "ioc_type":      r.ioc_type,
        "final_score":   r.final_score,
        "decision":      r.decision,
        "threshold":     r.threshold,
        "score_source":  r.score_source,
        "feeds_found":   r.feeds_found,
        "combined_tags": r.combined_tags,
        "first_seen":    r.first_seen,
        "age_days":      round(r.age_days, 2) if r.age_days < 9000 else None,
        "components": {
            "category_weight":     r.components.category_weight,
            "corroboration_score": r.components.corroboration_score,
            "freshness_score":     r.components.freshness_score,
            "rule_score":          r.components.rule_score,
            "ml_score":            r.components.ml_score,
            "ml_used":             r.components.ml_used,
            "ml_confidence":       r.components.ml_confidence,
            "ml_model_agreement":  r.components.ml_model_agreement,
        },
        "urlhaus": {
            "found":      r.urlhaus_record.found,
            "tags":       r.urlhaus_record.tags,
            "first_seen": r.urlhaus_record.first_seen,
            "confidence": r.urlhaus_record.confidence,
        },
        "abusech": {
            "found":      r.abusech_record.found,
            "tags":       r.abusech_record.tags,
            "first_seen": r.abusech_record.first_seen,
            "confidence": r.abusech_record.confidence,
        },
        "enforcement": {
            "ipset_target": r.ipset_target,
            "ttl_seconds":  r.ttl_seconds,
        },
        "ml_details": r.ml_details if r.components.ml_used else {},
    }
    return json.dumps(out, indent=2)


def build_parser():
    p = argparse.ArgumentParser(
        prog="cti_scorer",
        description=(
            "CTI scoring tool — queries URLhaus and Abuse.ch APIs, "
            "computes document formula score, falls back to URLPredictor "
            "ML model if no API record found."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python m1_cli.py 185.220.101.45
  python m1_cli.py malware-domain.ru
  python m1_cli.py http://phishing.site/login
  python m1_cli.py --json 45.95.168.10
  python m1_cli.py --verbose randomxyz.cc
  python m1_cli.py --batch ips.txt
  echo "8.8.8.8" | python m1_cli.py --stdin

Score formula:
  Score = Category_weight X Corroboration X Freshness
  ≥ 0.6 → ENFORCE (add to ipset)   < 0.6 → DISCARD
        """,
    )
    p.add_argument("value",       nargs="?",
                   help="IP, domain, or URL to score")
    p.add_argument("--json",      action="store_true", help="Output as JSON")
    p.add_argument("--verbose",   action="store_true",
                   help="Show raw API + ML detail")
    p.add_argument("--batch",     metavar="FILE",
                   help="Score each line of a file")
    p.add_argument("--stdin",     action="store_true",
                   help="Read values from stdin (one per line)")
    p.add_argument("--no-color",  action="store_true",
                   help="Disable ANSI colour codes")
    p.add_argument("--quiet",     action="store_true",
                   help="Only print score and decision")
    p.add_argument("--threshold", type=float, default=ENFORCE_THRESHOLD,
                   help=f"Override enforce threshold (default: {ENFORCE_THRESHOLD})")
    p.add_argument("--log-level", default="WARNING",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                   help="Logging verbosity")
    return p


def _score_and_print(value: str, args) -> CTIResult:
    global ENFORCE_THRESHOLD
    ENFORCE_THRESHOLD = args.threshold

    r = score(value)

    if args.quiet:
        print(f"{r.value}\t{r.final_score:.4f}\t{r.decision}")
        return r

    formatted = (
        _fmt_json(r) if args.json else
        _fmt_verbose(r) if args.verbose else
        _fmt_plain(r)
    )

    if args.no_color:
        formatted = re.sub(r'\033\[[0-9;]*m', '', formatted)

    print(formatted)
    return r


def main():
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    if args.batch:
        try:
            with open(args.batch) as f:
                values = [
                    ln.strip() for ln in f
                    if ln.strip() and not ln.startswith('#')
                ]
        except FileNotFoundError:
            print(f"[!] File not found: {args.batch}", file=sys.stderr)
            sys.exit(1)

        if args.json:
            print(json.dumps(
                [json.loads(_fmt_json(score(v))) for v in values],
                indent=2,
            ))
        else:
            for v in values:
                _score_and_print(v, args)
        return

    if args.stdin:
        if args.json:
            results = []
            for line in sys.stdin:
                v = line.strip()
                if v and not v.startswith('#'):
                    results.append(json.loads(_fmt_json(score(v))))
            print(json.dumps(results, indent=2))
        else:
            for line in sys.stdin:
                v = line.strip()
                if v and not v.startswith('#'):
                    _score_and_print(v, args)
        return

    if not args.value:
        parser.print_help()
        sys.exit(0)

    _score_and_print(args.value, args)


if __name__ == "__main__":
    main()
