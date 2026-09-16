"""
app.py — Domain Intelligence : fiche d'évaluation d'un nom de domaine.

Lancement :
    .venv/Scripts/python.exe app.py
puis http://127.0.0.1:5001

Fonctionnalités :
  * saisie d'un domaine, interrogation d'API externes (RDAP, DNS, géolocalisation IP, TLS)
  * fiche de résultats
  * niveau de risque argumenté
  * enregistrement dans Supabase (ou stockage local si Supabase n'est pas configuré)
  * historique consultable, réaffichable et supprimable
"""
import logging
import sys

from flask import (Flask, abort, jsonify, redirect, render_template, request,
                   url_for)
from werkzeug.serving import make_server

import analyzer
import config
import db
from providers import rdap

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("app")

BASE_DIR = config.BASE_DIR
app = Flask(__name__,
            template_folder=str(BASE_DIR / "web" / "templates"),
            static_folder=str(BASE_DIR / "web" / "static"))
app.secret_key = config.SUPABASE_KEY or "domain-intelligence-local"


@app.template_filter("dt")
def format_datetime(value):
    """Affiche un horodatage ISO de façon lisible : 2026-09-15T18:35:23+00:00 -> 2026-09-15 18:35:23."""
    if not value:
        return "—"
    return str(value).replace("T", " ")[:19]


@app.context_processor
def inject_globals():
    """Variables et filtres disponibles dans tous les gabarits."""
    return {
        "backend": db.backend_status(),
        "supabase_configured": config.supabase_configured(),
        "humanize_age": analyzer.humanize_age,
    }


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html", result=None, error=None, saved=None)


@app.route("/analyze", methods=["POST", "GET"])
def analyze_route():
    raw = (request.form.get("domain") if request.method == "POST"
           else request.args.get("domain")) or ""
    if not raw.strip():
        return render_template("index.html", result=None,
                               error="Saisis un nom de domaine.", saved=None)

    try:
        result = analyzer.analyze(raw)
    except analyzer.InvalidDomain as exc:
        logger.warning("Saisie refusée : %r (%s)", raw, exc)
        return render_template("index.html", result=None, error=str(exc), saved=None), 400
    except Exception as exc:                                  # noqa: BLE001
        logger.exception("Analyse impossible pour %r", raw)
        return render_template("index.html", result=None,
                               error=f"Analyse impossible : {type(exc).__name__}: {exc}",
                               saved=None), 500

    saved = db.save_analysis(result)
    if saved.get("ok"):
        logger.info("Analyse de %s enregistrée (backend %s, id %s)",
                    result["domain"], saved.get("backend"), saved.get("id"))
    else:
        logger.error("Enregistrement de %s impossible : %s", result["domain"], saved.get("error"))

    return render_template("index.html", result=result, error=None, saved=saved)


@app.route("/history")
def history():
    search = (request.args.get("q") or "").strip()
    listing = db.list_analyses(limit=200, search=search)
    stats = db.statistics()
    return render_template("history.html", listing=listing, stats=stats, search=search)


@app.route("/analysis/<analysis_id>")
def analysis_detail(analysis_id):
    row = db.get_analysis(analysis_id)
    if not row:
        abort(404)
    # Supabase renvoie la fiche complète dans 'payload' ; le stockage local
    # stocke directement l'objet complet.
    record = row.get("payload") if isinstance(row.get("payload"), dict) else row
    record = dict(record)
    record["id"] = row.get("id")
    return render_template("index.html", result=record, error=None,
                           saved={"ok": True, "backend": db.backend_status()["backend"]},
                           from_history=True)


# --------------------------------------------------------------------------
# API JSON
# --------------------------------------------------------------------------
@app.route("/api/analyze", methods=["POST", "GET"])
def api_analyze():
    """Analyse en JSON. ?save=0 pour ne pas enregistrer le résultat."""
    raw = ""
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        raw = payload.get("domain") or request.form.get("domain") or ""
    else:
        raw = request.args.get("domain", "")

    save = request.args.get("save", "1") not in ("0", "false", "no")
    try:
        result = analyzer.analyze(raw)
    except analyzer.InvalidDomain as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except rdap.RdapError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502
    except Exception as exc:                                  # noqa: BLE001
        logger.exception("Analyse impossible pour %r", raw)
        return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 500

    saved = db.save_analysis(result) if save else {"ok": False, "skipped": True}
    result.pop("raw", None)
    return jsonify({"ok": True, "analysis": result, "saved": saved})


@app.route("/api/history")
def api_history():
    limit = min(int(request.args.get("limit", 50)), 500)
    search = request.args.get("q", "")
    listing = db.list_analyses(limit=limit, search=search)
    rows = []
    for row in listing.get("rows", []):
        rows.append({key: row.get(key) for key in
                     ("id", "domain", "registrar", "country", "ip",
                      "domain_age_days", "risk_level", "risk_score", "analyzed_at")})
    return jsonify({"ok": listing.get("ok", False), "count": len(rows),
                    "backend": listing.get("backend"), "results": rows,
                    "error": listing.get("error")})


@app.route("/api/analysis/<analysis_id>")
def api_analysis(analysis_id):
    row = db.get_analysis(analysis_id)
    if not row:
        return jsonify({"ok": False, "error": "Analyse introuvable."}), 404
    record = row.get("payload") if isinstance(row.get("payload"), dict) else row
    record = dict(record)
    record["id"] = row.get("id")
    record.pop("raw", None)
    return jsonify({"ok": True, "analysis": record})


@app.route("/api/analysis/<analysis_id>", methods=["DELETE"])
def api_delete(analysis_id):
    result = db.delete_analysis(analysis_id)
    return jsonify(result), (200 if result.get("ok") else 400)


@app.route("/api/status")
def api_status():
    return jsonify({"ok": True, "storage": db.backend_status(),
                    "statistics": db.statistics(),
                    "risk_thresholds": {"medium": config.RISK_MEDIUM_THRESHOLD,
                                        "high": config.RISK_HIGH_THRESHOLD}})


@app.errorhandler(404)
def not_found(_error):
    return render_template("404.html"), 404


def main() -> int:
    # Les analyses qu'une panne réseau avait laissées de côté repartent vers
    # Supabase dès le démarrage.
    renvoi = db.flush_pending()
    if renvoi.get("flushed"):
        logger.info("Démarrage : %d analyse(s) en attente renvoyée(s) vers Supabase.",
                    renvoi["flushed"])
    en_attente = db.pending_count()

    banner = f"""
{'=' * 68}
  DOMAIN INTELLIGENCE — analyse de fiabilité d'un nom de domaine
{'=' * 68}
  URL          : http://{config.HOST}:{config.PORT}
  Stockage     : {db.backend_status()['message']}
  API externe  : RDAP (rdap.org), ip-api.com, TLS direct
  En attente   : {en_attente} analyse(s) à renvoyer vers Supabase
{'=' * 68}
"""
    print(banner, flush=True)
    logger.info("Démarrage sur http://%s:%s", config.HOST, config.PORT)
    server = make_server(config.HOST, config.PORT, app, threaded=True)
    try:
        return server.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt du serveur.", flush=True)
        return 0


if __name__ == "__main__":
    sys.exit(main())
