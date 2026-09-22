"""
providers/network.py — Vérification HTTPS et lecture du certificat TLS.

CE QUI A ÉTÉ DÉPLACÉ, ET POURQUOI

Ce module contenait trois fonctions supplémentaires, retirées :

  * `resolve_ips` et `dns_records` interrogeaient le résolveur du système
    d'exploitation. Le résultat dépendait donc de la machine qui lançait
    l'analyse — une même fiche pouvait annoncer des adresses différentes selon
    l'endroit, sans qu'aucune des deux réponses ne soit fausse. Remplacées par
    `providers/dns_doh.py`, qui interroge deux résolveurs publics en HTTPS.

  * `lookup_ip` interrogeait ip-api.com, joignable uniquement en HTTP sur son
    offre gratuite : les requêtes circulaient en clair. Remplacée par
    `providers/ip_info.py`, qui distingue le propriétaire officiel du bloc
    (donnée de registre) de sa localisation estimée.

CE QUI RESTE ICI, ET POURQUOI

Ces deux vérifications sont conservées parce qu'elles sont exactes et qu'aucun
service externe ne peut les remplacer : elles interrogent directement le serveur
du domaine analysé, sans intermédiaire.

  * `check_https` établit si le domaine répond réellement en HTTPS et où il
    redirige. Un service tiers ne peut pas le dire à notre place : il faut
    frapper à la porte soi-même.

  * `tls_certificate` lit le certificat présenté, y compris quand il est
    invalide — c'est justement dans ce cas que l'information est la plus utile.
"""
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests

from config import HTTP_TIMEOUT, USER_AGENT

logger = logging.getLogger(__name__)


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
            result["redirects_to_other_host"] = host not in (domain, f"www.{domain}")
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
    """
    Détails du certificat TLS présenté : émetteur, validité, nom couvert.

    Complémentaire de `providers/ssl_labs.py` : ici on lit ce que le serveur
    présente réellement et à cet instant, y compris un certificat expiré ou
    auto-signé. SSL Labs, lui, donne une note globale de configuration, mais sa
    réponse peut dater de plusieurs heures et n'est pas toujours disponible.
    """
    info: Dict[str, Any] = {"issuer": None, "subject": None, "not_before": None,
                            "not_after": None, "days_until_expiry": None,
                            "expired": None, "error": None}
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
        expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        # Comparaison avec un horodatage conscient du fuseau : l'ancienne
        # version utilisait utcnow(), déprécié, et pouvait produire un décalage
        # d'un jour près des changements de date.
        maintenant = datetime.now(timezone.utc).replace(tzinfo=None)
        info["days_until_expiry"] = (expiry - maintenant).days
        info["expired"] = info["days_until_expiry"] < 0
    except (KeyError, ValueError):
        pass
    return info
