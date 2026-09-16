"""
config.py — Configuration de l'application (variables d'environnement).

Aucune clé n'est écrite en dur. Copie .env.example en .env et remplis les valeurs
Supabase ; sans elles, l'application fonctionne avec un stockage local.
"""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# --------------------------------------------------------------------------
# Supabase (optionnel — repli automatique sur stockage local si absent)
# --------------------------------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip().rstrip("/")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "").strip()
SUPABASE_TABLE = os.getenv("SUPABASE_TABLE", "domain_analyses").strip()
# Clé de secours, utilisée UNIQUEMENT si la RLS refuse l'écriture avec la clé anon.
# Elle reste côté serveur (jamais envoyée au navigateur). À retirer du .env dès
# que les politiques RLS sont en place.
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "").strip()

# --------------------------------------------------------------------------
# API externes (aucune clé requise)
# --------------------------------------------------------------------------
RDAP_ENDPOINT = os.getenv("RDAP_ENDPOINT", "https://rdap.org/domain/{domain}")
IP_API_ENDPOINT = os.getenv("IP_API_ENDPOINT", "http://ip-api.com/json/{ip}")
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "15"))
USER_AGENT = os.getenv("USER_AGENT", "domain-intelligence/1.0 (projet pedagogique)")

# --------------------------------------------------------------------------
# Stockage local (utilisé si Supabase n'est pas configuré)
# --------------------------------------------------------------------------
STORAGE_DIR = BASE_DIR / "storage"
LOCAL_HISTORY_FILE = STORAGE_DIR / "history.json"
# Analyses qui n'ont pas pu être écrites dans Supabase (réseau coupé, panne
# passagère). Elles y sont renvoyées automatiquement dès que la connexion
# revient : aucune analyse n'est perdue.
PENDING_FILE = STORAGE_DIR / "pending.json"
# Nombre de tentatives d'écriture avant de mettre une analyse en attente.
SUPABASE_RETRIES = int(os.getenv("SUPABASE_RETRIES", "3"))

# --------------------------------------------------------------------------
# Serveur web
# --------------------------------------------------------------------------
HOST = os.getenv("APP_HOST", "127.0.0.1")
PORT = int(os.getenv("APP_PORT", "5001"))
DEBUG = os.getenv("APP_DEBUG", "0") == "1"

# --------------------------------------------------------------------------
# Seuils de risque
# --------------------------------------------------------------------------
RISK_MEDIUM_THRESHOLD = int(os.getenv("RISK_MEDIUM_THRESHOLD", "25"))
RISK_HIGH_THRESHOLD = int(os.getenv("RISK_HIGH_THRESHOLD", "55"))


def supabase_configured() -> bool:
    return bool(SUPABASE_URL and SUPABASE_KEY)


def storage_backend() -> str:
    return "supabase" if supabase_configured() else "local"
