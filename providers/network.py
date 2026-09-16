"""
providers/network.py — Résolution DNS, géolocalisation IP et vérification HTTPS.

Aucune clé API : on utilise le résolveur système (stdlib socket), ip-api.com
(gratuit, 45 requêtes/minute) et une requête HTTPS directe avec vérification du
certificat.
"""
import logging
import socket
import ssl
from typing import Any, Dict, List, Optional, Tuple

import requests

from config import HTTP_TIMEOUT, IP_API_ENDPOINT, USER_AGENT

logger = logging.getLogger(__name__)

try:                      # dnspython est optionnel : l'app fonctionne sans
    import dns.resolver
    _HAS_DNSPYTHON = True
except ImportError:       # pragma: no cover
    _HAS_DNSPYTHON = False


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------
def resolve_ips(domain: str, timeout: float = 5.0) -> Tuple[List[str], Optional[str]]:
    """Résout les adresses IPv4 du domaine. Retourne (liste, erreur)."""
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(domain, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        ips = sorted({info[4][0] for info in infos})
        return ips, None
    except socket.gaierror as exc:
        return [], f"Nom non résolu ({exc.strerror or exc})"
    except Exception as exc:                                  # noqa: BLE001
        return [], f"{type(exc).__name__}: {exc}"
    finally:
        socket.setdefaulttimeout(previous)


def dns_records(domain: str) -> Dict[str, Any]:
    """Récupère NS / MX / TXT via dnspython (silencieux si indisponible)."""
    records: Dict[str, Any] = {"ns": [], "mx": [], "txt": [], "available": _HAS_DNSPYTHON}
    if not _HAS_DNSPYTHON:
        return records
    for rtype in ("NS", "MX", "TXT"):
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=6)
            if rtype == "MX":
                records["mx"] = sorted(str(r.exchange).rstrip(".").lower() for r in answers)
            elif rtype == "TXT":
                records["txt"] = [b"".join(r.strings).decode("utf-8", "replace")[:200] for r in answers][:5]
            else:
                records["ns"] = sorted(str(r.target).rstrip(".").lower() for r in answers)
        except Exception:                                     # noqa: BLE001
            continue
    return records


# --------------------------------------------------------------------------
# Géolocalisation IP
# --------------------------------------------------------------------------
def lookup_ip(ip: str) -> Dict[str, Any]:
    """
    Interroge ip-api.com pour une IP.
    Retourne un dict toujours exploitable (champs vides + 'error' en cas d'échec).
    """
    result: Dict[str, Any] = {
        "ip": ip, "country": None, "country_code": None, "region": None, "city": None,
        "isp": None, "org": None, "asn": None, "hosting": None, "proxy": None, "error": None,
    }
    try:
        response = requests.get(
            IP_API_ENDPOINT.format(ip=ip),
            params={"fields": "status,message,country,countryCode,regionName,city,isp,org,as,hosting,proxy"},
            headers={"User-Agent": USER_AGENT},
            timeout=HTTP_TIMEOUT,
        )
        payload = response.json()
    except requests.RequestException as exc:
        result["error"] = f"Géolocalisation indisponible : {exc}"
        return result
    except ValueError:
        result["error"] = "Réponse de géolocalisation illisible."
        return result

    if payload.get("status") != "success":
        result["error"] = payload.get("message", "IP non géolocalisable.")
        return result

    result.update({
        "country": payload.get("country"),
        "country_code": payload.get("countryCode"),
        "region": payload.get("regionName"),
        "city": payload.get("city"),
        "isp": payload.get("isp"),
        "org": payload.get("org"),
        "asn": payload.get("as"),
        "hosting": payload.get("hosting"),
        "proxy": payload.get("proxy"),
    })
    return result


# --------------------------------------------------------------------------
# HTTPS
# --------------------------------------------------------------------------
def check_https(domain: str) -> Dict[str, Any]:
    """
    Tente https://<domaine>. Vérifie le certificat TLS (les erreurs de
    certificat sont donc détectées et rapportées) et suit les redirections.
    """
    result: Dict[str, Any] = {
        "ok": False, "status_code": None, "final_url": None,
        "redirects_to_other_host": False, "error": None,
    }
    try:
        response = requests.get(
            f"https://{domain}",
            headers={"User-Agent": USER_AGENT},
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
        )
        result["ok"] = True
        result["status_code"] = response.status_code
        result["final_url"] = response.url
        try:
            host = response.url.split("//", 1)[1].split("/", 1)[0].split(":")[0].lower()
            result["redirects_to_other_host"] = host not in (domain, f"www.{domain}") and host != f"www.{domain}"
        except (IndexError, AttributeError):
            pass
    except requests.exceptions.SSLError as exc:
        result["error"] = f"Certificat TLS invalide : {str(exc)[:160]}"
    except requests.exceptions.ConnectionError as exc:
        result["error"] = f"Connexion impossible en HTTPS : {str(exc)[:120]}"
    except requests.exceptions.Timeout:
        result["error"] = "Délai dépassé (pas de réponse HTTPS)."
    except requests.RequestException as exc:
        result["error"] = f"{type(exc).__name__}: {str(exc)[:120]}"
    return result


def tls_certificate(domain: str) -> Dict[str, Any]:
    """Détails du certificat TLS : émetteur, validité, nom couvert."""
    info: Dict[str, Any] = {"issuer": None, "subject": None, "not_before": None,
                            "not_after": None, "days_until_expiry": None, "error": None}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=HTTP_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
    except Exception as exc:                                  # noqa: BLE001
        info["error"] = f"{type(exc).__name__}: {str(exc)[:120]}"
        return info

    def _flatten(field) -> Optional[str]:
        if not field:
            return None
        parts = []
        for entry in field:
            for key, value in entry:
                parts.append(f"{key}={value}")
        return ", ".join(parts)

    info["issuer"] = _flatten(cert.get("issuer"))
    info["subject"] = _flatten(cert.get("subject"))
    info["not_before"] = cert.get("notBefore")
    info["not_after"] = cert.get("notAfter")
    try:
        from datetime import datetime
        expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        info["days_until_expiry"] = (expiry - datetime.utcnow()).days
    except (KeyError, ValueError):
        pass
    return info
