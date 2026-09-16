"""
urlscan.py — API externe urlscan.io : réputation et télémétrie web.

urlscan.io charge une page dans un navigateur instrumenté puis publie le
résultat : hébergeur, pays, certificat TLS, redirections, ressources appelées.
Son API de recherche est **ouverte** — aucune clé, aucune inscription :

    GET https://urlscan.io/api/v1/search/?q=page.domain:<domaine>&size=1

Elle répond en JSON et fournit :
  * le nombre de scans publics déjà réalisés sur le domaine ;
  * son classement de popularité (Cisco Umbrella) ;
  * l'hébergeur réellement observé : serveur, IP, ASN, pays, DNS inverse ;
  * le certificat présenté au moment du scan : émetteur, date de validité ;
  * la date du dernier scan et le lien vers le rapport public.

C'est cette API qui permet de répondre à la question « ce domaine a-t-il déjà
été observé sur le web, et par qui est-il hébergé en réalité ? ».

Débit : l'API de recherche est plafonnée à quelques requêtes par minute. En cas
de refus (429) ou de panne, `lookup` lève UrlscanError ; analyzer.py consigne
alors la limite dans la fiche et l'analyse se poursuit sans ce signal.
"""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests

import config

logger = logging.getLogger(__name__)

SEARCH_URL = "https://urlscan.io/api/v1/search/"


class UrlscanError(RuntimeError):
    """L'API urlscan.io n'a pas pu être interrogée (quota, réseau, réponse illisible)."""


def lookup(domain: str) -> Dict[str, Any]:
    """
    Interroge l'API urlscan.io pour un domaine.

    Retourne un dictionnaire décrivant ce que l'API a observé. La clé
    « available » vaut True dès que l'API a répondu ; « total_scans » à 0
    signifie que le domaine n'a jamais été scanné publiquement, ce qui est une
    information en soi et non une erreur.
    """
    params = {"q": f"page.domain:{domain}", "size": 1}
    headers = {"User-Agent": config.USER_AGENT, "Accept": "application/json"}

    try:
        response = requests.get(SEARCH_URL, params=params, headers=headers,
                                timeout=config.HTTP_TIMEOUT)
    except requests.RequestException as exc:
        raise UrlscanError(
            f"urlscan.io injoignable ({exc.__class__.__name__}).") from exc

    if response.status_code == 429:
        raise UrlscanError("urlscan.io a refusé la requête (quota atteint, HTTP 429).")
    if response.status_code != 200:
        raise UrlscanError(f"urlscan.io a répondu HTTP {response.status_code}.")

    try:
        data = response.json()
    except ValueError as exc:
        raise UrlscanError("urlscan.io a renvoyé une réponse illisible.") from exc

    try:
        total = int(data.get("total") or 0)
    except (TypeError, ValueError):
        total = 0

    result: Dict[str, Any] = {
        "available": True,
        "source": "urlscan.io",
        "total_scans": total,
        "has_more": bool(data.get("has_more")),
    }

    # Domaine jamais observé : information exploitable, on s'arrête là.
    if total == 0:
        result["reputation"] = "jamais observé"
        return result

    scan = (data.get("results") or [{}])[0] or {}
    page = scan.get("page") or {}
    task = scan.get("task") or {}
    stats = scan.get("stats") or {}
    rank = page.get("umbrellaRank")

    result.update({
        "reputation": _reputation_label(rank),
        "popularity_rank": rank,
        "last_scan": task.get("time"),
        "last_scan_age_days": _days_since(task.get("time")),
        "server": page.get("server"),
        "observed_ip": page.get("ip"),
        "observed_asn": page.get("asn"),
        "observed_host": page.get("asnname"),
        "observed_country": page.get("country"),
        "observed_title": page.get("title"),
        "reverse_dns": page.get("ptr"),
        "page_status": page.get("status"),
        "redirected": page.get("redirected"),
        "tls_issuer": page.get("tlsIssuer"),
        "tls_valid_from": page.get("tlsValidFrom"),
        "unique_ips": stats.get("uniqIPs"),
        "unique_countries": stats.get("uniqCountries"),
        "requests": stats.get("requests"),
        "report_url": (f"https://urlscan.io/result/{task.get('uuid')}/"
                       if task.get("uuid") else None),
    })
    return result


def _reputation_label(rank: Optional[int]) -> str:
    """Traduit le classement de popularité en libellé lisible."""
    if rank is None:
        return "non classé"
    try:
        rank = int(rank)
    except (TypeError, ValueError):
        return "non classé"
    if rank <= 100_000:
        return "notoriété élevée"
    if rank <= 1_000_000:
        return "notoriété moyenne"
    return "notoriété faible"


def _days_since(moment: Optional[str]) -> Optional[int]:
    """Nombre de jours écoulés depuis un horodatage ISO renvoyé par l'API."""
    if not moment:
        return None
    try:
        date = datetime.fromisoformat(str(moment).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - date).days)
