"""
db.py — Persistance des analyses.

Deux backends, choisis automatiquement :
  * Supabase  — si SUPABASE_URL et SUPABASE_KEY sont définis dans .env
  * local     — sinon, un fichier JSON dans storage/history.json

L'interface est identique dans les deux cas, l'application ne sait pas lequel est
utilisé (sauf pour l'afficher dans l'interface). Le passage à Supabase ne demande
donc aucune modification du code : seulement deux variables d'environnement.

Garantie d'enregistrement : quand Supabase est configuré, chaque analyse doit y
arriver. Si l'écriture échoue pour une raison passagère (réseau coupé, DNS,
délai dépassé), l'écriture est retentée, puis l'analyse est mise en file
d'attente dans storage/pending.json et renvoyée automatiquement dès que la
connexion revient (flush_pending). Rien n'est perdu en silence.
"""
import json
import logging
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import config

logger = logging.getLogger(__name__)

_LOCK = threading.RLock()
_client = None
_client_error: Optional[str] = None
_service_client = None
_service_error: Optional[str] = None
_SERVICE_KEY_USED = False        # passe à True dès que la RLS a forcé le repli

# Colonnes indexées (celles qui servent aux listes et aux filtres) + une colonne
# JSONB 'payload' qui contient la fiche complète. Ainsi, l'historique peut être
# listé sans charger les détails, et la fiche reste intégralement consultable.
COLUMNS = [
    "domain", "registrar", "country", "ip", "domain_age_days",
    "risk_level", "risk_score", "analyzed_at", "payload",
]


# --------------------------------------------------------------------------
# Backend Supabase
# --------------------------------------------------------------------------
def _get_client():
    """Crée le client Supabase une seule fois. Retourne None si indisponible."""
    global _client, _client_error
    if not config.supabase_configured():
        return None
    if _client is not None:
        return _client
    try:
        from supabase import create_client
        _client = create_client(config.SUPABASE_URL, config.SUPABASE_KEY)
        _client_error = None
    except Exception as exc:                                  # noqa: BLE001
        _client_error = f"{type(exc).__name__}: {exc}"
        logger.error("Client Supabase indisponible : %s", _client_error)
        _client = None
    return _client


def _to_row(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prépare la ligne Supabase.

    On envoie volontairement PLUS de colonnes que la table n'en possède : la
    fonction save_analysis retire ensuite celles qui n'existent pas réellement
    (voir _insert_adaptive). Cela permet à l'application de fonctionner aussi
    bien avec la table minimale de l'énoncé (domain, registrar, country, ip,
    risk, analyzed_at) qu'avec la version enrichie.
    """
    row = {
        # colonnes présentes dans la table minimale de l'énoncé
        "domain": record.get("domain"),
        "registrar": record.get("registrar"),
        "country": record.get("country"),
        "ip": record.get("ip"),
        "risk": record.get("risk_level"),
        "analyzed_at": record.get("analyzed_at") or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        # date de création du domaine (colonne « created_date » de la table)
        "created_date": record.get("created_at_domain"),
        # colonnes optionnelles : présentes seulement si la table a été enrichie
        "risk_level": record.get("risk_level"),
        "risk_score": record.get("risk_score"),
        "domain_age_days": record.get("domain_age_days"),
        "tld": record.get("tld"),
        "asn": record.get("asn"),
        "isp": record.get("isp"),
        "https_ok": record.get("https_ok"),
        "created_at_domain": record.get("created_at_domain"),
        "expires_at": record.get("expires_at"),
        "risk_factors": record.get("risk_factors"),
        "risk_summary": record.get("risk_summary"),
        "payload": {k: v for k, v in record.items() if k != "payload"},
    }
    return row


def _is_rls_error(exc: Exception) -> bool:
    text = str(exc)
    return "42501" in text or "row-level security" in text.lower()


def _get_service_client():
    """Client construit avec la clé service (contourne la RLS). Utilisé en secours."""
    global _service_client, _service_error
    if not config.SUPABASE_SERVICE_KEY:
        return None
    if _service_client is not None:
        return _service_client
    try:
        from supabase import create_client
        _service_client = create_client(config.SUPABASE_URL, config.SUPABASE_SERVICE_KEY)
        _service_error = None
    except Exception as exc:                                  # noqa: BLE001
        _service_error = f"{type(exc).__name__}: {exc}"
        logger.error("Client Supabase (clé service) indisponible : %s", _service_error)
        _service_client = None
    return _service_client


# Colonnes que la table s'est révélée ne pas posséder : on ne les renvoie plus.
_DROPPED_COLUMNS: set = set()
_MISSING_RE = re.compile(r"Could not find the '([^']+)' column")


def _insert_adaptive(client, row: Dict[str, Any]) -> Tuple[Any, List[str]]:
    """
    Insère la ligne en retirant au besoin les colonnes absentes de la table.

    PostgREST renvoie PGRST204 en nommant la première colonne inconnue : on la
    retire et on recommence. Le résultat est mémorisé, donc le coût n'est payé
    qu'une seule fois par colonne.
    """
    attempt = {k: v for k, v in row.items() if k not in _DROPPED_COLUMNS}
    removed: List[str] = []

    for _ in range(len(row) + 2):
        try:
            response = client.table(config.SUPABASE_TABLE).insert(attempt).execute()
            return response, removed
        except Exception as exc:                              # noqa: BLE001
            match = _MISSING_RE.search(str(exc))
            if not match:
                raise
            column = match.group(1)
            if column not in attempt:
                raise
            attempt.pop(column)
            removed.append(column)
            _DROPPED_COLUMNS.add(column)
    raise RuntimeError("Impossible de trouver un jeu de colonnes accepté par la table.")


def _insert_result(client, row: Dict[str, Any], via_service: bool = False) -> Dict[str, Any]:
    """Insère et met en forme le retour attendu par le reste de l'application."""
    previously_dropped = set(_DROPPED_COLUMNS)
    response, removed = _insert_adaptive(client, row)
    rows = response.data or []
    result = {"ok": True, "backend": "supabase",
              "id": rows[0].get("id") if rows else None}
    newly = sorted(set(removed) - previously_dropped)
    if newly:
        # Un seul message, une seule fois par colonne et par exécution.
        logger.info("Table Supabase : %d colonne(s) non présentes, ignorées (%s). "
                    "Exécute supabase_setup.sql pour les ajouter et enregistrer la fiche complète.",
                    len(newly), ", ".join(newly))
        result["ignored_columns"] = newly
    if via_service:
        result["via_service_key"] = True
    return result


def _effective_client():
    """
    Client utilisé pour TOUTES les opérations Supabase.

    Le projet a la RLS activée sur domain_analyses sans politique pour la clé
    « anon » : celle-ci ne peut ni insérer, ni lire (une lecture refusée renvoie
    silencieusement 0 ligne, ce qui donnerait un historique vide sans erreur).
    Si SUPABASE_SERVICE_KEY est fournie dans .env, on l'utilise donc pour tout.

    Elle reste côté serveur : le navigateur ne la voit jamais. Elle deviendra
    inutile dès que les politiques RLS de supabase_setup.sql seront exécutées.
    """
    global _SERVICE_KEY_USED
    if config.SUPABASE_SERVICE_KEY:
        client = _get_service_client()
        if client is not None:
            _SERVICE_KEY_USED = True
            return client
    return _get_client()


def _error_hint(exc: Exception) -> str:
    text = str(exc)
    if "PGRST205" in text or "does not exist" in text or "relation" in text:
        return ("La table n'existe pas encore dans Supabase. "
                "Exécute le script supabase_setup.sql dans l'éditeur SQL.")
    if "Invalid API key" in text or "401" in text:
        return "Clé Supabase refusée : vérifie SUPABASE_KEY dans .env."
    if "row-level security" in text or "42501" in text:
        if config.SUPABASE_SERVICE_KEY:
            return ("Écriture refusée par la RLS, y compris avec la clé de secours. "
                    "Exécute les politiques du script supabase_setup.sql.")
        return ("Accès bloqué par les politiques RLS : la table interdit l'insertion "
                "avec la clé anon. Deux solutions — (1) exécuter les politiques du "
                "script supabase_setup.sql dans l'éditeur SQL Supabase (recommandé), "
                "(2) renseigner SUPABASE_SERVICE_KEY dans .env (dépannage uniquement).")
    return text


def _normalise_row(row: Any) -> Any:
    """
    Harmonise une ligne Supabase avec le format attendu par les gabarits.

    La table de l'énoncé nomme la colonne « risk » (et non « risk_level ») et
    stocke la date de création du domaine dans « created_date » (d'où l'âge est
    recalculé). On accepte les deux formats sans dupliquer le code d'affichage.
    """
    if not isinstance(row, dict):
        return row
    out = dict(row)
    if not out.get("risk_level") and out.get("risk"):
        out["risk_level"] = out["risk"]

    if not out.get("domain_age_days") and out.get("created_date"):
        try:
            created = datetime.fromisoformat(str(out["created_date"]).replace("Z", "+00:00"))
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            out["domain_age_days"] = (datetime.now(timezone.utc) - created).days
        except (TypeError, ValueError):
            pass
    return out


# --------------------------------------------------------------------------
# Backend local (fichier JSON)
# --------------------------------------------------------------------------
def _read_local() -> List[Dict[str, Any]]:
    try:
        with open(config.LOCAL_HISTORY_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
            return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []


def _write_local(rows: List[Dict[str, Any]]) -> None:
    config.STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = config.LOCAL_HISTORY_FILE.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(rows, handle, ensure_ascii=False, indent=2, default=str)
    tmp.replace(config.LOCAL_HISTORY_FILE)


# --------------------------------------------------------------------------
# File d'attente des écritures Supabase non abouties
# --------------------------------------------------------------------------
def _read_pending() -> List[Dict[str, Any]]:
    try:
        with open(config.PENDING_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []


def _write_pending(items: List[Dict[str, Any]]) -> None:
    config.STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = config.PENDING_FILE.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(items, handle, ensure_ascii=False, indent=2, default=str)
    tmp.replace(config.PENDING_FILE)


def pending_count() -> int:
    """Nombre d'analyses en attente de renvoi vers Supabase."""
    return len(_read_pending())


def _is_permanent(exc: Exception) -> bool:
    """Vrai si réessayer ne sert à rien : c'est la configuration qu'il faut corriger."""
    text = str(exc)
    return (bool(_MISSING_RE.search(text)) or _is_rls_error(exc)
            or "Invalid API key" in text or "PGRST205" in text)


def _insert_with_retry(client, record: Dict[str, Any]) -> Dict[str, Any]:
    """Insère en réessayant les pannes passagères (réseau coupé, DNS, délai dépassé)."""
    tentatives = max(1, config.SUPABASE_RETRIES)
    for essai in range(1, tentatives + 1):
        try:
            return _insert_result(client, _to_row(record),
                                  via_service=bool(config.SUPABASE_SERVICE_KEY))
        except Exception as exc:                              # noqa: BLE001
            if _is_permanent(exc) or essai == tentatives:
                raise
            logger.warning("Écriture Supabase échouée (essai %d/%d) : %s "
                           "— nouvelle tentative dans un instant.", essai, tentatives, exc)
            time.sleep(0.8 * essai)
    raise RuntimeError("Écriture Supabase impossible.")


def _deja_en_base(client, record: Dict[str, Any]) -> bool:
    """Idempotence : évite d'enregistrer deux fois une analyse renvoyée plus tard."""
    domaine = record.get("domain")
    moment = record.get("analyzed_at")
    if not domaine or not moment:
        return False
    try:
        response = (client.table(config.SUPABASE_TABLE).select("id")
                    .eq("domain", domaine).eq("analyzed_at", moment).limit(1).execute())
        return bool(response.data)
    except Exception:                                         # noqa: BLE001
        return False


def _mettre_en_attente(record: Dict[str, Any], error: str) -> Dict[str, Any]:
    """Conserve l'analyse localement pour la renvoyer plus tard. Rien n'est perdu."""
    item = {
        "record": {k: v for k, v in record.items() if k != "raw"},
        "queued_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "error": error,
    }
    pending = _read_pending()
    pending.append(item)
    try:
        _write_pending(pending)
    except OSError as exc:
        return {"ok": False, "backend": "supabase",
                "error": f"{error} — mise en attente impossible : {exc}"}
    logger.warning("Analyse de %s mise en attente (%d en file) — %s",
                   record.get("domain"), len(pending), error)
    return {"ok": False, "backend": "supabase", "queued": True, "pending": len(pending),
            "error": f"{error} — analyse mise en attente, renvoi automatique "
                     f"dès que Supabase répond."}


def flush_pending(limit: int = 20) -> Dict[str, Any]:
    """
    Renvoie vers Supabase les analyses laissées en attente.

    Appelée au démarrage et à chaque nouvelle analyse : la file se vide donc
    d'elle-même dès que la connexion revient. Ne lève jamais.
    """
    with _LOCK:
        pending = _read_pending()
        if not pending:
            return {"ok": True, "flushed": 0, "pending": 0}
        if not config.supabase_configured():
            return {"ok": False, "flushed": 0, "pending": len(pending)}
        client = _effective_client()
        if client is None:
            return {"ok": False, "flushed": 0, "pending": len(pending)}

        restants: List[Dict[str, Any]] = []
        envoyes = 0
        for item in pending[:limit]:
            record = item.get("record") if isinstance(item, dict) else None
            if not isinstance(record, dict):
                continue                       # entrée illisible : on l'abandonne
            try:
                if not _deja_en_base(client, record):
                    _insert_result(client, _to_row(record),
                                   via_service=bool(config.SUPABASE_SERVICE_KEY))
                envoyes += 1
            except Exception as exc:                      # noqa: BLE001
                logger.warning("Renvoi impossible pour %s : %s", record.get("domain"), exc)
                restants.append(item)
        restants.extend(pending[limit:])
        try:
            _write_pending(restants)
        except OSError as exc:
            logger.error("File d'attente non enregistrable : %s", exc)
        if envoyes:
            logger.info("File d'attente : %d analyse(s) renvoyée(s) vers Supabase, "
                        "%d restante(s).", envoyes, len(restants))
        return {"ok": True, "flushed": envoyes, "pending": len(restants)}


# --------------------------------------------------------------------------
# API publique
# --------------------------------------------------------------------------
def backend_status() -> Dict[str, Any]:
    """État du stockage, affiché dans l'interface."""
    if config.supabase_configured():
        client = _get_client()
        if client is None:
            return {"backend": "supabase", "ready": False,
                    "message": f"Client Supabase non initialisé : {_client_error}"}
        message = f"Supabase — table « {config.SUPABASE_TABLE} »"
        if config.SUPABASE_SERVICE_KEY:
            message += " — accès via la clé service (RLS fermée à la clé anon)"
        etat = {"backend": "supabase", "ready": True, "message": message,
                "service_key_used": bool(config.SUPABASE_SERVICE_KEY)}
        en_attente = pending_count()
        if en_attente:
            etat["pending"] = en_attente
            etat["message"] += f" — {en_attente} analyse(s) en attente de renvoi"
        return etat
    return {"backend": "local", "ready": True,
            "message": "Stockage local (storage/history.json) — Supabase non configuré"}


def save_analysis(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enregistre une analyse dans Supabase.

    Retourne {"ok": bool, "id": ..., "backend": ..., "error": ...} et ne lève
    jamais : l'échec d'enregistrement ne doit pas faire perdre la fiche affichée
    à l'analyste. Si Supabase est configuré mais momentanément injoignable,
    l'analyse est retentée puis mise en file d'attente (flush_pending) au lieu
    d'être perdue.
    """
    with _LOCK:
        if config.supabase_configured():
            flush_pending()                     # on vide la file au passage
            client = _effective_client()
            if client is None:
                return _mettre_en_attente(
                    record,
                    f"Client Supabase non initialisé : {_client_error or _service_error}")
            try:
                return _insert_with_retry(client, record)
            except Exception as exc:                          # noqa: BLE001
                logger.exception("Échec d'insertion Supabase")
                hint = _error_hint(exc)
                if _is_permanent(exc):
                    # Configuration à corriger : mettre en attente ne servirait à rien.
                    return {"ok": False, "backend": "supabase", "error": hint}
                return _mettre_en_attente(record, hint)

        rows = _read_local()
        next_id = max((row.get("id", 0) for row in rows), default=0) + 1
        row = dict(record)
        row["id"] = next_id
        rows.append(row)
        try:
            _write_local(rows)
        except OSError as exc:
            return {"ok": False, "backend": "local", "error": f"Écriture impossible : {exc}"}
        return {"ok": True, "backend": "local", "id": next_id}


def list_analyses(limit: int = 50, search: str = "") -> Dict[str, Any]:
    """Historique des analyses, de la plus récente à la plus ancienne."""
    with _LOCK:
        if config.supabase_configured():
            client = _effective_client()
            if client is None:
                return {"ok": False, "rows": [], "error": f"Client Supabase non initialisé : {_client_error or _service_error}"}
            try:
                query = client.table(config.SUPABASE_TABLE).select("*")
                if search:
                    query = query.ilike("domain", f"%{search}%")
                response = query.order("analyzed_at", desc=True).limit(limit).execute()
                return {"ok": True, "backend": "supabase",
                        "rows": [_normalise_row(r) for r in (response.data or [])]}
            except Exception as exc:                          # noqa: BLE001
                logger.exception("Lecture Supabase impossible")
                return {"ok": False, "rows": [], "backend": "supabase", "error": _error_hint(exc)}

        rows = _read_local()
        if search:
            rows = [r for r in rows if search.lower() in str(r.get("domain", "")).lower()]
        rows.sort(key=lambda r: str(r.get("analyzed_at", "")), reverse=True)
        return {"ok": True, "rows": rows[:limit], "backend": "local"}


def get_analysis(analysis_id: Any) -> Optional[Dict[str, Any]]:
    with _LOCK:
        if config.supabase_configured():
            client = _effective_client()
            if client is None:
                return None
            try:
                response = (client.table(config.SUPABASE_TABLE)
                            .select("*").eq("id", analysis_id).limit(1).execute())
                rows = response.data or []
                return _normalise_row(rows[0]) if rows else None
            except Exception as exc:                          # noqa: BLE001
                logger.exception("Lecture Supabase impossible")
                return None

        for row in _read_local():
            if str(row.get("id")) == str(analysis_id):
                return row
        return None


def delete_analysis(analysis_id: Any) -> Dict[str, Any]:
    with _LOCK:
        if config.supabase_configured():
            client = _effective_client()
            if client is None:
                return {"ok": False, "error": f"Client Supabase non initialisé : {_client_error or _service_error}"}
            try:
                client.table(config.SUPABASE_TABLE).delete().eq("id", analysis_id).execute()
                return {"ok": True, "backend": "supabase"}
            except Exception as exc:                          # noqa: BLE001
                return {"ok": False, "backend": "supabase", "error": _error_hint(exc)}

        rows = _read_local()
        remaining = [r for r in rows if str(r.get("id")) != str(analysis_id)]
        if len(remaining) == len(rows):
            return {"ok": False, "backend": "local", "error": "Analyse introuvable."}
        _write_local(remaining)
        return {"ok": True, "backend": "local"}


def statistics() -> Dict[str, Any]:
    """Compteurs affichés en tête de l'historique."""
    result = list_analyses(limit=10000)
    rows = result.get("rows", [])
    counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    for row in rows:
        level = str(row.get("risk_level", "")).upper()
        if level in counts:
            counts[level] += 1
    return {"total": len(rows), "by_level": counts, "ok": result.get("ok", False)}
