# main.py
import os
import json
import zipfile
import tempfile
import py7zr
import shutil
import re
from datetime import datetime
from collections import defaultdict, Counter
from typing import List, Dict, Any, Optional

import pandas as pd
import requests

from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# -------------------- Configuration --------------------
# Put sensitive values in environment variables (do NOT hardcode)
WATSONX_API_KEY = os.getenv("WATSONX_API_KEY")  # example: export WATSONX_API_KEY="..."
WATSONX_URL = os.getenv("WATSONX_URL", "https://eu-de.ml.cloud.ibm.com")  # adjust if needed
PROJECT_ID = os.getenv("WATSONX_PROJECT_ID")  # optional

UPLOAD_DIR = os.path.join(os.getcwd(), "uploaded_logs")
os.makedirs(UPLOAD_DIR, exist_ok=True)

CLASSIFIED_LOGS_JSON = os.path.join(os.getcwd(), "classified_logs.json")
MITRE_FILE = os.path.join(os.getcwd(), "mitre_data", "enterprise-attack.json")  # ensure file present

# -------------------- FastAPI app --------------------
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------- Utilities: I/O --------------------
def read_file(path: str) -> Optional[str]:
    encodings = ["utf-8", "utf-16", "utf-32", "latin1", "utf-8-sig"]
    for enc in encodings:
        try:
            with open(path, "r", encoding=enc, errors="ignore") as f:
                return f.read()
        except Exception:
            continue
    return None

def read_csv_file(path: str) -> Optional[pd.DataFrame]:
    for enc in ("utf-8", "utf-16", "utf-32", "latin1"):
        try:
            df = pd.read_csv(path, encoding=enc, on_bad_lines="skip")
            if df.empty:
                return None
            return df
        except Exception:
            continue
    return None

# -------------------- Archive extraction --------------------
def extract_7z(archive_path: str, out_dir: str, password: Optional[str] = None):
    try:
        with py7zr.SevenZipFile(archive_path, mode="r", password=password) as archive:
            archive.extractall(path=out_dir)
        return True, None
    except py7zr.exceptions.PasswordRequired as e:
        return False, "password_required"
    except Exception as e:
        return False, str(e)

def extract_zip(archive_path: str, out_dir: str, password: Optional[str] = None):
    try:
        if password:
            with zipfile.ZipFile(archive_path, "r") as z:
                z.extractall(path=out_dir, pwd=password.encode())
        else:
            with zipfile.ZipFile(archive_path, "r") as z:
                z.extractall(path=out_dir)
        return True, None
    except RuntimeError as e:
        # often wrong password raises RuntimeError
        return False, "password_required"
    except Exception as e:
        return False, str(e)

def extract_archive(archive_path: str, out_dir: str, password: Optional[str] = None) -> Dict[str, Any]:
    """Extract .7z or .zip to out_dir. Returns dict with status & message."""
    os.makedirs(out_dir, exist_ok=True)
    if archive_path.lower().endswith(".7z"):
        ok, msg = extract_7z(archive_path, out_dir, password=password)
    elif archive_path.lower().endswith(".zip"):
        ok, msg = extract_zip(archive_path, out_dir, password=password)
    else:
        return {"ok": False, "message": "unsupported_format"}

    return {"ok": ok, "message": msg}

# -------------------- IOC and MITRE helpers --------------------
STOPWORDS = {"the","a","an","and","or","for","to","of","in","on","by","with","via","over","under","using","use","from","into","at","as"}
TACTIC_WEIGHTS = {
    "reconnaissance": 2, "resource-development": 2, "initial-access": 4, "execution": 4,
    "persistence": 3, "privilege-escalation": 4, "defense-evasion": 4, "credential-access": 5,
    "discovery": 2, "lateral-movement": 5, "collection": 3, "command-and-control": 5,
    "exfiltration": 5, "impact": 5,
}
IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "ipv6": re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b"),
    "url": re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE),
    "domain": re.compile(r"\b(?!(?:\d{1,3}\.){3}\d{1,3})(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "hash": re.compile(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b"),
    "filepath": re.compile(r"(?:[A-Za-z]:\\|/)(?:[^\\/\n]+[\\/]?)+"),
    "registry": re.compile(r"\bHKEY_[A-Z_\\]+\\[^\s]+", re.IGNORECASE),
    "timestamp": re.compile(r"\b(?:\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?|\d{2}/\d{2}/\d{4}[ T]\d{2}:\d{2}:\d{2})\b"),
}
def extract_iocs(text: str) -> Dict[str, List[str]]:
    return {k: list(set(p.findall(text))) for k, p in IOC_PATTERNS.items()}

def _tokenize_name(name: str) -> List[str]:
    name = name.lower()
    tokens = re.split(r"[^a-z0-9]+", name)
    return [t for t in tokens if t and t not in STOPWORDS]

# -------------------- Load MITRE index --------------------
def load_mitre_index(mitre_path: str) -> Dict[str, Any]:
    if not os.path.exists(mitre_path):
        raise FileNotFoundError(f"MITRE file not found at {mitre_path}")
    with open(mitre_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    by_id = {}
    name_to_id = {}
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        ext = obj.get("external_references", [])
        tech_id = None
        for ref in ext:
            if ref.get("source_name") in ("mitre-attack", "mitre-ics-attack", "mitre-mobile-attack"):
                tech_id = ref.get("external_id")
                break
        if not tech_id:
            continue
        tactics = [kc.get("phase_name") for kc in obj.get("kill_chain_phases", []) if kc.get("kill_chain_name") == "mitre-attack"]
        name = obj.get("name", "").strip()
        desc = obj.get("description", "") or ""
        keywords = set(_tokenize_name(name))
        by_id[tech_id] = {"name": name, "tactics": tactics, "desc": desc, "keywords": keywords}
        name_to_id[name.lower()] = tech_id
    return {"by_id": by_id, "name_to_id": name_to_id}

# load once at startup
try:
    MITRE_INDEX = load_mitre_index(MITRE_FILE)
except Exception as e:
    MITRE_INDEX = {"by_id": {}, "name_to_id": {}}
    print(f"⚠️ Warning: MITRE file load failed: {e}")

def score_match(tactics: List[str], match_type: str) -> float:
    base = 2.0 if match_type == "full" else 1.0
    return base + sum(TACTIC_WEIGHTS.get(t, 0) * 0.1 for t in tactics)

def risk_from_iocs(iocs: Dict[str, List[str]]) -> float:
    score = 0.0
    score += len(iocs.get("ipv4", [])) * 1.5
    score += len(iocs.get("ipv6", [])) * 1.5
    score += len(iocs.get("domain", [])) * 1.0
    score += len(iocs.get("url", [])) * 2.0
    score += len(iocs.get("email", [])) * 0.5
    score += len(iocs.get("hash", [])) * 2.0
    score += len(iocs.get("registry", [])) * 1.0
    return score

def severity_from_score(score: float) -> str:
    if score >= 40:
        return "critical"
    if score >= 25:
        return "high"
    if score >= 12:
        return "medium"
    return "low"

# -------------------- Recursive loader (handles nested archives) --------------------
def load_logs_from_folder(main_folder: str, password: Optional[str] = None) -> List[Dict[str, Any]]:
    all_logs: List[Dict[str, Any]] = []
    scanned_files: List[str] = []

    for root, dirs, files in os.walk(main_folder):
        for fname in files:
            file_path = os.path.join(root, fname)
            scanned_files.append(file_path)

            # If it's an archive, extract it into nested folder and recurse
            if fname.lower().endswith((".7z", ".zip")):
                nested_dir = os.path.join(root, f"{fname}_extracted")
                res = extract_archive(file_path, nested_dir, password=password)
                if not res.get("ok"):
                    # if password required, bubble up a special entry (do not crash)
                    if res.get("message") == "password_required":
                        print(f"⚠️ Archive requires password: {file_path}")
                    else:
                        print(f"⚠️ Failed to extract nested archive {file_path}: {res.get('message')}")
                    continue
                all_logs.extend(load_logs_from_folder(nested_dir, password=password))
                continue

            try:
                # text logs
                if fname.lower().endswith((".txt", ".log")):
                    txt = read_file(file_path)
                    if txt:
                        all_logs.append({"filename": file_path, "text": txt})

                # CSV; look for 'text' column rows
                elif fname.lower().endswith(".csv"):
                    df = read_csv_file(file_path)
                    if df is None:
                        continue
                    # If a 'text' column exists, read per-row; else join all text-like columns into a string
                    if "text" in df.columns:
                        for _, row in df.iterrows():
                            all_logs.append({"filename": file_path, "text": str(row.get("text", ""))})
                    else:
                        # fallback: join rows into one large string to classify
                        joined = "\n".join(df.astype(str).apply(lambda r: " ".join(r.values), axis=1).tolist())
                        if joined.strip():
                            all_logs.append({"filename": file_path, "text": joined})

                # JSON logs (list-of-events or object)
                elif fname.lower().endswith(".json"):
                    txt = read_file(file_path)
                    if not txt:
                        continue
                    try:
                        data = json.loads(txt)
                        if isinstance(data, list):
                            for entry in data:
                                all_logs.append({"filename": file_path, "text": json.dumps(entry)})
                        else:
                            all_logs.append({"filename": file_path, "text": json.dumps(data)})
                    except Exception:
                        # not strict JSON (maybe newline-delimited JSON?), fallback to raw text
                        if txt.strip():
                            all_logs.append({"filename": file_path, "text": txt})
            except Exception as e:
                print(f"⚠️ Error reading {file_path}: {e}")
                continue

    # debug prints
    if not scanned_files:
        print("⚠️ No files found in extracted folder at all.")
    elif not all_logs:
        print(f"⚠️ Found {len(scanned_files)} files, but none matched (.txt, .log, .csv, .json).")
        print("Example files:", scanned_files[:8])

    return all_logs

# -------------------- Classifier (single unified pipeline) --------------------
def classify_logs_pipeline(all_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Output schema per entry:
    {
      "filename": "...",
      "text": "...",
      "iocs": {...},
      "matched": [ {"id","name","tactics","match_type","score"} ... ],
      "file_risk_score": float
    }
    """
    by_id = MITRE_INDEX.get("by_id", {})
    classified = []

    for entry in all_logs:
        raw = entry.get("text", "")
        text_l = raw.lower()
        iocs = extract_iocs(raw)

        matched = []
        # iterate MITRE techniques
        for tid, meta in by_id.items():
            name = meta.get("name", "").lower()
            tactics = meta.get("tactics", [])
            keywords = meta.get("keywords", set())

            full = name and (name in text_l)
            hits = sum(1 for kw in keywords if re.search(rf"\b{re.escape(kw)}\b", text_l))
            partial = hits >= 2

            if full or partial:
                mtype = "full" if full else "partial"
                matched.append({
                    "id": tid,
                    "name": meta.get("name"),
                    "tactics": tactics,
                    "match_type": mtype,
                    "score": round(score_match(tactics, mtype), 3)
                })

        file_score = round(sum(m["score"] for m in matched) + risk_from_iocs(iocs), 3)
        classified.append({
            "filename": entry.get("filename"),
            "text": raw,
            "iocs": iocs,
            "matched": matched,
            "file_risk_score": file_score
        })
    return classified

# -------------------- Report builder --------------------
def build_deep_report(classified: List[Dict[str, Any]]) -> Dict[str, Any]:
    tactic_counts = defaultdict(int)
    technique_counts = Counter()
    all_iocs = defaultdict(set)
    per_file = []

    for entry in classified:
        for k, vals in entry.get("iocs", {}).items():
            for v in vals:
                all_iocs[k].add(v)
        for m in entry.get("matched", []):
            technique_counts[(m["id"], m["name"])] += 1
            for t in m.get("tactics", []):
                tactic_counts[t] += 1
        per_file.append({
            "filename": entry["filename"],
            "risk_score": entry.get("file_risk_score", 0),
            "top_techniques": sorted(
                [{"id": m["id"], "name": m["name"], "match_type": m["match_type"], "score": m["score"]} for m in entry.get("matched", [])],
                key=lambda x: x["score"], reverse=True
            )[:5],
            "ioc_counts": {k: len(entry.get("iocs", {}).get(k, [])) for k in IOC_PATTERNS.keys()}
        })

    total_score = sum(e.get("file_risk_score", 0) for e in classified)
    overall_severity = severity_from_score(total_score)

    # convert numeric score to "percentage" style (0-100)
    max_score = max(total_score, 1)  # avoid divide by zero
    risk_percent = min(round((total_score / (total_score + 100)) * 100), 100)

    tactic_breakdown = [{"tactic": t, "count": c} for t, c in sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)]
    top_techniques = [{"id": tid, "name": name, "count": cnt} for (tid, name), cnt in technique_counts.most_common(15)]
    ioc_summary = {k: sorted(list(v))[:500] for k, v in all_iocs.items()}

    # build narrative
    narrative = []
    if tactic_breakdown:
        lead = tactic_breakdown[0]["tactic"].replace("-", " ")
        narrative.append(f"Activity is dominated by {lead} with additional evidence across {len(tactic_breakdown)} ATT&CK stages.")
    if top_techniques:
        t0 = top_techniques[0]
        narrative.append(f"Most frequent technique observed: {t0['id']} — {t0['name']}.")
    if ioc_summary.get("url") or ioc_summary.get("domain"):
        narrative.append("Network indicators (domains/URLs) were identified; review egress/DNS logs.")
    if ioc_summary.get("hash"):
        narrative.append("File hashes were found; consider retro-hunting in EDR/AV.")
    narrative_text = "\n".join(narrative) or "No significant malicious patterns detected."

    # markdown-ready report with line breaks
    md = [
        "# Deep Incident Report",
        f"- Generated: {datetime.utcnow().isoformat()}Z",
        f"- Total Logs: {len(classified)}",
        f"- Distinct Techniques: {len(technique_counts)}",
        f"- Tactics Observed: {len(tactic_counts)}",
        f"- Overall Risk: {overall_severity} ({risk_percent}%)",
        "",
        "## Narrative",
        narrative_text,
        "",
        "## Tactics Breakdown",
    ]
    for t in tactic_breakdown:
        md.append(f"- **{t['tactic'].replace('-', ' ').title()}**: {t['count']} hits")
    md.append("")
    md.append("## Top Techniques")
    for t in top_techniques:
        md.append(f"- **{t['id']}** — {t['name']}: {t['count']} hits")
    md.append("")
    md.append("## IOC Summary")
    for k, vals in ioc_summary.items():
        md.append(f"- **{k.upper()}** ({len(vals)}): {', '.join(vals[:10])}{' ...' if len(vals) > 10 else ''}")

    with open("report.md", "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))

    return {
        "summary": {
            "total_logs": len(classified),
            "distinct_techniques": len(technique_counts),
            "tactics_observed": len(tactic_counts),
            "overall_severity": overall_severity,
            "risk_percent": risk_percent
        },
        "tactics_breakdown": tactic_breakdown,
        "top_techniques": top_techniques,
        "ioc_summary": ioc_summary,
        "files": sorted(per_file, key=lambda x: x["risk_score"], reverse=True)[:200],
        "narrative": narrative_text,
        "generated_at": datetime.utcnow().isoformat() + "Z"
    }

# -------------------- API Endpoints --------------------
@app.post("/upload-logs")
async def upload_logs(file: UploadFile = File(...), password: str = Form(None), action: str = Form(...)):
    # if action == "check-status":
    #     return {"output": "✅ Server is running fine."}

    # 1. Save uploaded file
    temp_dir = tempfile.mkdtemp()
    file_path = os.path.join(temp_dir, file.filename)
    with open(file_path, "wb") as f:
        f.write(await file.read())

    # 2. Extract
    extract_dir = tempfile.mkdtemp()
    try:
        if file.filename.endswith(".zip"):
            with zipfile.ZipFile(file_path, "r") as zip_ref:
                zip_ref.extractall(extract_dir)
            print(f"✅ Extracted ZIP to {extract_dir}")

        elif file.filename.endswith(".7z"):
            import py7zr
            with py7zr.SevenZipFile(file_path, mode="r", password=password) as archive:
                archive.extractall(path=extract_dir)
            print(f"✅ Extracted 7z to {extract_dir}")

        else:
            return {"output": f"⚠️ Unsupported archive format: {file.filename}"}

    except Exception as e:
        return {"output": f"❌ Extraction failed: {str(e)}"}

    # 3. Load logs
    logs = load_logs_from_folder(extract_dir)
    print(f"📊 Parsed {len(logs)} logs from extracted folder")

    if not logs:
        return {"output": f"⚠️ No valid log files found in {extract_dir}"}

    # 4. Process with Watson (placeholder for now)
    return {"output": f"✅ Processed {len(logs)} logs successfully"}

@app.get("/api/report")
def quick_report():
    """Return a small summary from classified_logs.json"""
    try:
        with open(CLASSIFIED_LOGS_JSON, "r", encoding="utf-8") as fh:
            classified = json.load(fh)
    except FileNotFoundError:
        return JSONResponse({"error": "No classified logs found. Upload and analyze first."}, status_code=404)

    techniques = set()
    iocs = defaultdict(list)
    for entry in classified:
        for m in entry.get("matched", []):
            techniques.add(f"{m.get('id')} - {m.get('name')}")
        for k, vals in entry.get("iocs", {}).items():
            iocs[k].extend(vals)

    return {
        "total_logs": len(classified),
        "techniques_detected": list(sorted(techniques))[:200],
        "ioc_summary": {k: list({v for v in vals}) for k, vals in iocs.items()}
    }

@app.get("/api/report/deep")
def deep_report():
    try:
        with open(CLASSIFIED_LOGS_JSON, "r", encoding="utf-8") as fh:
            classified = json.load(fh)
    except FileNotFoundError:
        return JSONResponse({"error": "No classified logs found. Upload and analyze first."}, status_code=404)

    report = build_deep_report(classified)
    return report

@app.get("/send_to_watsonx")
def send_to_watsonx():
    """
    Placeholder: attempt to POST classified logs to Watsonx if env vars configured.
    NOTE: different Watsonx products expect different ingestion endpoints; adjust accordingly.
    """
    if not WATSONX_API_KEY or not PROJECT_ID:
        return JSONResponse({"status": "error", "detail": "WATSONX_API_KEY and WATSONX_PROJECT_ID must be set as environment variables. This endpoint is a helper; update endpoint/credentials before use."}, status_code=400)

    try:
        with open(CLASSIFIED_LOGS_JSON, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except FileNotFoundError:
        return JSONResponse({"status": "error", "detail": "No classified logs found."}, status_code=404)

    # This is intentionally generic — update URL/path per your IBM docs
    url = f"{WATSONX_URL}/v1/projects/{PROJECT_ID}/ingest"
    headers = {
        "Authorization": f"Bearer {WATSONX_API_KEY}",
        "Content-Type": "application/json"
    }
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        r.raise_for_status()
        return {"status": "success", "watsonx_response": r.json()}
    except requests.exceptions.RequestException as e:
        return JSONResponse({"status": "error", "detail": str(e)}, status_code=500)
    return {"output": "Log analysis completed and results sent to Watsonx."}

@app.get("/check-status")
def check_status():
    return {"output": "✅ Server is running fine."}

