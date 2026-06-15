#!/usr/bin/env python3
"""
app.py — Local web UI for the Microsoft Defender for Cloud assessment tool.

Wraps mdc_assess.run_assessment() in a small Flask app so you can run an
assessment from the browser instead of the command line: pick a subscription and
framework, optionally enable AI analysis, watch progress, then view and download
the HTML / JSON / CSV reports.

IMPORTANT — local use only:
    Authentication uses InteractiveBrowserCredential, which opens a browser window
    on the machine running this server (not the client's browser). Run this on your
    own workstation and connect from the same machine. It binds to 127.0.0.1 by
    default. Do not expose it on a shared host or public network.

Run:
    pip install flask
    python app.py                 # then open http://127.0.0.1:5000
    python app.py --port 8000 --host 127.0.0.1
"""

import argparse
import os
import tempfile
import threading
import uuid
from datetime import datetime, timezone

from flask import (Flask, abort, jsonify, redirect, render_template,
                   request, send_file, url_for)

app = Flask(__name__)

# In-memory job registry. Keyed by job id. Local single-user tool, so a plain
# dict guarded by a lock is sufficient (no external job store needed).
_JOBS = {}
_JOBS_LOCK = threading.Lock()

DOWNLOAD_KINDS = {
    "json": ("mdc_report.json", "application/json", True),
    "html": ("mdc_report.html", "text/html", False),
    "csv":  ("mdc_report.csv", "text/csv", True),
    "ai":   ("mdc_ai_analysis.json", "application/json", True),
}

AI_TASKS = ["explain", "prioritize", "guidance", "review"]
FRAMEWORKS = ["cis", "nist", "none"]


# ── Job helpers ────────────────────────────────────────────────────────────────

def _new_job(subscription_id, framework, ai_task):
    job_id = uuid.uuid4().hex
    job = {
        "id": job_id,
        "status": "queued",
        "subscription_id": subscription_id or "",
        "framework": framework,
        "ai_task": ai_task or "",
        "messages": [],
        "error": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "output_dir": tempfile.mkdtemp(prefix=f"mdc_run_{job_id[:8]}_"),
        "files": {},        # kind -> absolute path
        "summary": None,    # {percentage, total, counts}
        "ai_content": None,
        "ai_configured": None,
    }
    with _JOBS_LOCK:
        _JOBS[job_id] = job
    return job


def _get_job(job_id):
    with _JOBS_LOCK:
        return _JOBS.get(job_id)


def _log(job, message):
    job["messages"].append(message)


def _resolve_subscription(credential, supplied_id):
    """Resolve a subscription without blocking on stdin (web-safe).

    Uses the supplied id when given. Otherwise auto-selects when exactly one
    subscription is visible; raises if the account has several so the user can
    pick one in the form.
    """
    if supplied_id:
        return supplied_id
    from azure.mgmt.subscription import SubscriptionClient
    subs = list(SubscriptionClient(credential).subscriptions.list())
    if not subs:
        raise RuntimeError("No subscriptions found for this account.")
    if len(subs) == 1:
        return subs[0].subscription_id
    names = ", ".join(f"{s.display_name} ({s.subscription_id})" for s in subs)
    raise RuntimeError(
        "Multiple subscriptions are visible — specify one in the form. "
        f"Available: {names}"
    )


def _run_job(job):
    """Background worker: authenticate, assess, render reports, optional AI."""
    try:
        job["status"] = "authenticating"
        _log(job, "Authenticating (a browser window may open on this machine)...")

        # Lazy imports so the app starts even without the Azure SDK installed.
        try:
            from azure.identity import (InteractiveBrowserCredential,
                                        TokenCachePersistenceOptions)
            from azure.mgmt.security import SecurityCenter
            from mdc_assess import run_assessment, save_report
            from report_generator import (generate_html_report,
                                          generate_csv_report)
        except ImportError as e:
            raise RuntimeError(
                f"Required package not installed: {e}. "
                "Run: pip install -r requirements.txt"
            )

        credential = InteractiveBrowserCredential(
            cache_persistence_options=TokenCachePersistenceOptions(name="mdc_assess")
        )

        sub_id = _resolve_subscription(credential, job["subscription_id"])
        job["subscription_id"] = sub_id
        _log(job, f"Using subscription: {sub_id}")

        client = SecurityCenter(credential, sub_id)

        job["status"] = "assessing"
        _log(job, f"Running assessment (framework: {job['framework']})...")
        report_data = run_assessment(client, sub_id, job["framework"])

        out = job["output_dir"]
        json_path = save_report(report_data, os.path.join(out, "mdc_report.json"))
        html_path = generate_html_report(report_data, os.path.join(out, "mdc_report.html"))
        csv_path = generate_csv_report(report_data, os.path.join(out, "mdc_report.csv"))
        job["files"].update({"json": json_path, "html": html_path, "csv": csv_path})

        recs = report_data.get("recommendations", {}) or {}
        score = report_data.get("secure_score", {}) or {}
        job["summary"] = {
            "percentage": score.get("percentage"),
            "total": recs.get("total", 0),
            "counts": recs.get("counts", {}),
        }
        _log(job, f"Assessment complete: {recs.get('total', 0)} findings.")

        # Optional AI analysis.
        if job["ai_task"]:
            job["status"] = "ai"
            _log(job, f"Running AI analysis ({job['ai_task']})...")
            try:
                from ai_agent import run_task, AIError
                result = run_task(
                    report_data, job["ai_task"],
                    output_path=os.path.join(out, "mdc_ai_analysis.json"),
                    quiet=True,
                )
                if result is None:
                    job["ai_configured"] = False
                    _log(job, "AI not configured (set MDC_AI_* env vars). Skipped.")
                else:
                    job["ai_configured"] = True
                    job["ai_content"] = result.get("content")
                    job["files"]["ai"] = os.path.join(out, "mdc_ai_analysis.json")
                    _log(job, "AI analysis complete.")
            except AIError as e:
                _log(job, f"AI analysis failed: {e}")
            except ImportError:
                _log(job, "AI module unavailable; skipped.")

        job["status"] = "done"
        _log(job, "Done.")

    except Exception as e:  # noqa: BLE001 — surface any failure to the UI
        job["status"] = "error"
        job["error"] = str(e)
        _log(job, f"Error: {e}")


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html", frameworks=FRAMEWORKS, ai_tasks=AI_TASKS)


@app.route("/run", methods=["POST"])
def run():
    subscription_id = (request.form.get("subscription_id") or "").strip()
    framework = request.form.get("framework", "cis")
    ai_task = request.form.get("ai_task", "")

    if framework not in FRAMEWORKS:
        abort(400, "Invalid framework.")
    if ai_task and ai_task not in AI_TASKS:
        abort(400, "Invalid AI task.")

    job = _new_job(subscription_id, framework, ai_task)
    threading.Thread(target=_run_job, args=(job,), daemon=True).start()
    return redirect(url_for("status_page", job_id=job["id"]))


@app.route("/status/<job_id>")
def status_page(job_id):
    job = _get_job(job_id)
    if not job:
        abort(404)
    return render_template("status.html", job=job)


@app.route("/api/status/<job_id>")
def api_status(job_id):
    job = _get_job(job_id)
    if not job:
        abort(404)
    return jsonify({
        "id": job["id"],
        "status": job["status"],
        "messages": job["messages"],
        "error": job["error"],
        "summary": job["summary"],
        "framework": job["framework"],
        "ai_task": job["ai_task"],
        "ai_configured": job["ai_configured"],
        "ai_content": job["ai_content"],
        "subscription_id": job["subscription_id"],
        "available": sorted(job["files"].keys()),
    })


@app.route("/report/<job_id>")
def report(job_id):
    job = _get_job(job_id)
    if not job:
        abort(404)
    path = job["files"].get("html")
    if not path or not os.path.exists(path):
        abort(404, "Report not ready.")
    # Inline so the self-contained HTML report renders in the browser.
    return send_file(path, mimetype="text/html")


@app.route("/download/<job_id>/<kind>")
def download(job_id, kind):
    if kind not in DOWNLOAD_KINDS:
        abort(404)
    job = _get_job(job_id)
    if not job:
        abort(404)
    path = job["files"].get(kind)
    if not path or not os.path.exists(path):
        abort(404, "File not ready.")
    filename, mimetype, as_attachment = DOWNLOAD_KINDS[kind]
    return send_file(path, mimetype=mimetype, as_attachment=as_attachment,
                     download_name=filename)


def main():
    parser = argparse.ArgumentParser(description="Local web UI for the MDC assessment tool.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address (default: 127.0.0.1 — local only)")
    parser.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    args = parser.parse_args()

    if args.host not in ("127.0.0.1", "localhost"):
        print("[WARN] Binding to a non-local address. This tool opens a browser for "
              "auth on the server and is intended for local use only.")

    print(f"\n[INFO] MDC assessment web UI on http://{args.host}:{args.port}")
    print("[INFO] Authentication opens a browser on THIS machine. Local use only.\n")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
