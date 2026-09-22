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
# Sources de données externes
#
# Deux catégories, volontairement séparées :
#
#   * sans clé — le fournisseur est interrogeable immediatement, rien a
#     installer. Ce sont des services publics adosses a des organisations
#     reconnues (ICANN, Cloudflare, Google, Qualys, crt.sh) ;
#   * avec clé — le fournisseur est plus riche mais exige un compte gratuit.
#     Laissé vide, il est simplement ignoré et l'analyse se poursuit : l'outil
#     ne casse pas faute de clé, il perd une source.
# --------------------------------------------------------------------------

# Serveurs DNS publics joints en HTTPS. Interroger deux résolveurs
# indépendants permet de croiser leurs réponses : un accord rend la mesure
# fiable, une divergence signale une propagation en cours ou une manipulation.
DOH_CLOUDFLARE = os.getenv("DOH_CLOUDFLARE",
                           "https://cloudflare-dns.com/dns-query")
DOH_GOOGLE = os.getenv("DOH_GOOGLE", "https://dns.google/resolve")
DNS_TIMEOUT = float(os.getenv("DNS_TIMEOUT", "6"))

# Registre des noms de domaine (protocole officiel de l'ICANN).
RDAP_ENDPOINT = os.getenv("RDAP_ENDPOINT", "https://rdap.org/domain/{domain}")

# Note de version : l'ancien fournisseur de géolocalisation (ip-api.com) est
# abandonné. Il n'était joignable qu'en HTTP — donc en clair — sur son offre
# gratuite, et sa précision de localisation est très inférieure à celle des
# bases professionnelles. Remplacé par IPinfo (voir IPINFO_TOKEN).
IPINFO_ENDPOINT = os.getenv("IPINFO_ENDPOINT", "https://ipinfo.io/{ip}/json")
# Facultatif. Sans jeton, la géolocalisation passe par le repli gratuit décrit
# dans providers/ip_info.py.
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "").strip()

# Réputation : VirusTotal agrège le verdict de plus de 70 moteurs antivirus et
# de listes de blocage. C'est la référence mondiale du domaine. Compte gratuit
# — 4 requêtes/minute, 500/jour. Sans clé, la source est ignorée.
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY", "").strip()
VIRUSTOTAL_ENDPOINT = os.getenv("VIRUSTOTAL_ENDPOINT",
                                "https://www.virustotal.com/api/v3/domains/{domain}")

# Réputation d'adresse IP : signalements d'abus par des administrateurs.
# Compte gratuit — 1 000 vérifications/jour.
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "").strip()
ABUSEIPDB_ENDPOINT = os.getenv("ABUSEIPDB_ENDPOINT",
                               "https://api.abuseipdb.com/api/v2/check")

# Analyse approfondie de la configuration TLS, par Qualys SSL Labs.
# Service gratuit et sans clé, référence du domaine : la note attribuée (A+ à F)
# est immédiatement compréhensible, y compris par un non-spécialiste.
#
# L'analyse est ASYNCHRONE : on lance la demande, puis on interroge jusqu'à ce
# que le résultat soit prêt. Cela prend couramment 30 à 90 secondes, contre 2 à
# 4 secondes pour le reste de l'analyse. Le délai ci-dessous borne l'attente ;
# au-delà, la fiche indique que la note n'était pas disponible plutôt que de
# faire patienter l'utilisateur.
SSLLABS_ENABLED = os.getenv("SSLLABS_ENABLED", "1") == "1"
SSLLABS_ENDPOINT = os.getenv("SSLLABS_ENDPOINT",
                             "https://api.ssllabs.com/api/v3/analyze")
SSLLABS_MAX_WAIT = float(os.getenv("SSLLABS_MAX_WAIT", "45"))

# Journaux publics de transparence des certificats. Chaque certificat émis pour
# un domaine y est inscrit, ce qui révèle les sous-domaines réellement utilisés
# — y compris ceux qu'aucune page ne mentionne.
CRTSH_ENDPOINT = os.getenv("CRTSH_ENDPOINT", "https://crt.sh/")
CRTSH_ENABLED = os.getenv("CRTSH_ENABLED", "1") == "1"

HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "15"))
USER_AGENT = os.getenv("USER_AGENT", "domain-intelligence/1.1")

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
# En hébergement conteneurisé (Railway, Render, Fly.io), la plateforme impose
# son propre port via la variable PORT et attend une écoute sur 0.0.0.0 : une
# écoute sur 127.0.0.1 y est injoignable et produit « l'application n'a pas
# répondu ». PORT prime donc sur APP_HOST, qui reste à 127.0.0.1 dans .env pour
# l'usage local.
_PLATFORM_PORT = os.getenv("PORT", "").strip()
PORT = int(_PLATFORM_PORT or os.getenv("APP_PORT", "5001"))
HOST = "0.0.0.0" if _PLATFORM_PORT else os.getenv("APP_HOST", "127.0.0.1")
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
