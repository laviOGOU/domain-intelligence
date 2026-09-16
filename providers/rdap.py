"""
providers/rdap.py — Interrogation de RDAP (Registration Data Access Protocol).

RDAP est le successeur normalisé de WHOIS : même type d'informations (registrar,
dates de création/expiration, serveurs de noms, statuts), mais en JSON et sans
quota à clé. Aucun compte n'est nécessaire.

Source : https://rdap.org/domain/<domaine>  (redirige vers le registre faisant
autorité, ex. rdap.verisign.com pour les .com).
"""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from config import HTTP_TIMEOUT, RDAP_ENDPOINT, USER_AGENT

logger = logging.getLogger(__name__)


class RdapError(Exception):
    """Échec de l'interrogation RDAP."""


class DomainNotFound(RdapError):
    """Le domaine n'est pas enregistré (ou le registre ne publie pas de RDAP)."""


def _vcard_value(entity: Dict[str, Any], field: str) -> Optional[str]:
    """Extrait un champ d'une vCard RDAP (fn, adr, email, tel...)."""
    vcard = entity.get("vcardArray")
    if not vcard or len(vcard) < 2:
        return None
    for item in vcard[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        if item[0] == field:
            value = item[3]
            if isinstance(value, list):
                # adr : [pobox, ext, street, locality, region, code postal, pays]
                parts = [str(p) for p in value if p]
                return ", ".join(parts) if parts else None
            return str(value) if value else None
    return None


def _vcard_country(entity: Dict[str, Any]) -> Optional[str]:
    """Extrait le pays d'une vCard RDAP (dernier élément du champ adr)."""
    vcard = entity.get("vcardArray")
    if not vcard or len(vcard) < 2:
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "adr":
            value = item[3]
            if isinstance(value, list) and len(value) >= 7:
                code, country = value[5], value[6]
                if country:
                    return str(country)
                if code:
                    return str(code)
    return None


def _find_entities(entities: List[Dict[str, Any]], role: str) -> List[Dict[str, Any]]:
    """Cherche récursivement les entités portant un rôle donné (ex. 'registrar')."""
    found = []
    for entity in entities or []:
        if role in (entity.get("roles") or []):
            found.append(entity)
        found.extend(_find_entities(entity.get("entities") or [], role))
    return found


def _parse_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def lookup(domain: str) -> Dict[str, Any]:
    """
    Interroge RDAP pour un domaine et retourne un dict normalisé.

    Lève DomainNotFound si le domaine n'est pas enregistré,
    RdapError pour tout autre échec (réseau, réponse illisible).
    """
    url = RDAP_ENDPOINT.format(domain=domain)
    try:
        response = requests.get(
            url,
            headers={"Accept": "application/rdap+json", "User-Agent": USER_AGENT},
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        raise RdapError(f"Réseau indisponible : {exc}") from exc

    if response.status_code == 404:
        raise DomainNotFound("Domaine non enregistré (aucun enregistrement RDAP).")
    if response.status_code == 429:
        raise RdapError("Quota RDAP dépassé (429). Réessaie dans quelques minutes.")
    if response.status_code >= 400:
        raise RdapError(f"RDAP a répondu {response.status_code}.")

    try:
        data = response.json()
    except ValueError as exc:
        raise RdapError("Réponse RDAP illisible (JSON invalide).") from exc

    # --- Événements : enregistrement / expiration / dernière modification ---
    events: Dict[str, datetime] = {}
    for event in data.get("events", []) or []:
        action = (event.get("eventAction") or "").lower()
        parsed = _parse_date(event.get("eventDate"))
        if action and parsed:
            events[action] = parsed

    created = events.get("registration")
    expires = events.get("expiration")
    updated = events.get("last changed") or events.get("last update of rdap database")

    age_days = None
    if created:
        age_days = (datetime.now(timezone.utc) - created).days

    days_until_expiry = None
    if expires:
        days_until_expiry = (expires - datetime.now(timezone.utc)).days

    # --- Registrar (+ pays déclaré par le registrar) ---
    registrars = _find_entities(data.get("entities") or [], "registrar")
    registrar_name = None
    registrar_country = None
    registrar_id = None
    if registrars:
        registrar = registrars[0]
        registrar_name = _vcard_value(registrar, "fn")
        registrar_country = _vcard_country(registrar)
        registrar_id = registrar.get("handle")
        if not registrar_name:
            registrar_name = registrar_id

    # --- Registrant (titulaire) : souvent masqué pour cause de RGPD ---
    registrants = _find_entities(data.get("entities") or [], "registrant")
    registrant_country = None
    registrant_redacted = False
    if registrants:
        registrant_country = _vcard_country(registrants[0])
        registrant_redacted = not bool(_vcard_value(registrants[0], "fn"))

    nameservers = [ns.get("ldhName", "").lower()
                   for ns in (data.get("nameservers") or []) if ns.get("ldhName")]

    return {
        "source": "RDAP",
        "registry_handle": data.get("handle"),
        "ldh_name": (data.get("ldhName") or domain).lower(),
        "registrar": registrar_name,
        "registrar_id": registrar_id,
        "registrar_country": registrar_country,
        "registrant_country": registrant_country,
        "registrant_redacted": registrant_redacted,
        "created_at": created.isoformat() if created else None,
        "expires_at": expires.isoformat() if expires else None,
        "updated_at": updated.isoformat() if updated else None,
        "age_days": age_days,
        "days_until_expiry": days_until_expiry,
        "status": data.get("status") or [],
        "nameservers": nameservers,
        "rdap_url": response.url,
    }
