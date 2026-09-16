"""
analyzer.py — Orchestration : domaine saisi -> collecte -> risque -> fiche.

Les appels réseau sont lancés en parallèle : une analyse complète prend
généralement 2 à 4 secondes, contre une quinzaine en séquentiel.
"""
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import risk
from providers import network, rdap, urlscan

logger = logging.getLogger(__name__)

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)

# Suffixes publics composés courants : permet d'extraire le bon TLD (ex. co.uk).
MULTI_PART_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.za", "com.br", "com.mx", "co.jp", "co.in", "com.cn", "com.tr",
}


class InvalidDomain(ValueError):
    """Le texte saisi n'est pas un nom de domaine exploitable."""


def normalize_domain(raw: str) -> str:
    """
    Nettoie une saisie utilisateur et retourne le domaine nu, en minuscules.

    Accepte : "https://www.Example.com/path?x=1", "Example.COM", " example.com "
    Retourne : "example.com"
    Lève InvalidDomain si la saisie n'est pas un domaine plausible.
    """
    if not raw or not str(raw).strip():
        raise InvalidDomain("Aucun domaine saisi.")

    text = str(raw).strip()

    # Une URL complète est acceptée : on ne garde que l'hôte.
    if "//" in text:
        text = urlparse(text).netloc or text
    elif "/" in text:
        text = text.split("/", 1)[0]
    elif "@" in text:
        text = text.split("@", 1)[1]        # adresse e-mail -> domaine

    text = text.strip().lower().rstrip(".")
    if text.startswith("www."):
        text = text[4:]
    text = text.split(":", 1)[0]            # retire un éventuel :port

    # IDN : "mairie-évry.fr" -> "xn--mairie-vry-..." reste valide, on se contente
    # de valider la forme ASCII obtenue.
    try:
        text.encode("idna")
    except UnicodeError as exc:
        raise InvalidDomain("Nom de domaine non convertible en IDN.") from exc

    if not DOMAIN_RE.match(text):
        raise InvalidDomain(
            "Format invalide. Attendu : un domaine du type exemple.com "
            "(au moins un point, sans espace ni caractère interdit)."
        )
    return text


def get_tld(domain: str) -> str:
    """Retourne l'extension réelle en tenant compte des suffixes composés."""
    parts = domain.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_TLDS:
        return ".".join(parts[-2:])
    return parts[-1] if len(parts) > 1 else ""


def _resolve_and_locate(domain: str) -> Tuple[List[str], Optional[str], Dict[str, Any]]:
    """Résolution DNS puis géolocalisation de la première adresse trouvée."""
    ips, error = network.resolve_ips(domain)
    ip_info: Dict[str, Any] = {}
    if ips:
        ip_info = network.lookup_ip(ips[0])
    return ips, error, ip_info


def analyze(domain: str) -> Dict[str, Any]:
    """
    Analyse complète d'un domaine et retourne la fiche prête à afficher.

    Ne lève jamais pour un simple échec réseau : les erreurs sont consignées dans
    le champ 'errors' de chaque section, la fiche reste consultable.
    """
    domain = normalize_domain(domain)
    tld = get_tld(domain)
    errors: List[str] = []

    rdap_data: Dict[str, Any] = {}
    registered = True
    rdap_available = True

    with ThreadPoolExecutor(max_workers=6) as pool:
        future_rdap = pool.submit(rdap.lookup, domain)
        future_dns = pool.submit(network.dns_records, domain)
        future_ips = pool.submit(_resolve_and_locate, domain)
        future_https = pool.submit(network.check_https, domain)
        future_tls = pool.submit(network.tls_certificate, domain)
        future_urlscan = pool.submit(urlscan.lookup, domain)

        try:
            rdap_data = future_rdap.result()
        except rdap.DomainNotFound as exc:
            # Le domaine n'existe pas : c'est un résultat, pas une panne.
            registered = False
            errors.append(f"RDAP : {exc}")
        except rdap.RdapError as exc:
            # Panne ou quota : on ne peut rien conclure sur l'enregistrement.
            rdap_available = False
            errors.append(f"RDAP : {exc}")

        try:
            dns_data = future_dns.result()
        except Exception as exc:                              # noqa: BLE001
            dns_data = {"ns": [], "mx": [], "txt": [], "available": False}
            errors.append(f"DNS : {type(exc).__name__}: {exc}")

        try:
            ips, dns_error, ip_info = future_ips.result()
        except Exception as exc:                              # noqa: BLE001
            ips, dns_error, ip_info = [], f"{type(exc).__name__}: {exc}", {}
        if dns_error:
            errors.append(f"Résolution DNS : {dns_error}")

        try:
            https_data = future_https.result()
        except Exception as exc:                              # noqa: BLE001
            https_data = {"ok": False, "status_code": None, "final_url": None,
                          "redirects_to_other_host": False, "error": str(exc)}
            errors.append(f"HTTPS : {exc}")

        try:
            tls_data = future_tls.result()
        except Exception as exc:                              # noqa: BLE001
            tls_data = {"error": str(exc)}
            errors.append(f"TLS : {exc}")

        try:
            urlscan_data = future_urlscan.result()
        except urlscan.UrlscanError as exc:
            # API externe indisponible ou quota atteint : limite signalée, pas
            # de pénalité (voir risk.evaluate).
            urlscan_data = {"available": False, "source": "urlscan.io", "error": str(exc)}
            errors.append(f"urlscan.io : {exc}")
        except Exception as exc:                              # noqa: BLE001
            urlscan_data = {"available": False, "source": "urlscan.io",
                            "error": f"{type(exc).__name__}: {exc}"}
            errors.append(f"urlscan.io : {type(exc).__name__}: {exc}")

    if not registered:
        rdap_data = {"registrar": None, "age_days": None, "status": [],
                     "nameservers": [], "source": "RDAP (non enregistré)"}

    payload = {
        "domain": domain,
        "tld": tld,
        "rdap": rdap_data,
        "ip": ip_info,
        "https": https_data,
        "dns": dns_data,
        "urlscan": urlscan_data,
        "registered": registered,
        "rdap_available": rdap_available,
    }
    evaluation = risk.evaluate(payload)

    # Le pays affiché est celui de l'hébergement (le plus parlant), avec repli
    # sur le pays du registrar puis du titulaire.
    country = (ip_info.get("country") or rdap_data.get("registrar_country")
               or rdap_data.get("registrant_country"))

    age_days = rdap_data.get("age_days")
    record: Dict[str, Any] = {
        "domain": domain,
        "tld": tld,
        "registered": registered,
        "registrar": rdap_data.get("registrar"),
        "registrar_id": rdap_data.get("registrar_id"),
        "country": country,
        "country_code": ip_info.get("country_code") or None,
        "registrar_country": rdap_data.get("registrar_country"),
        "registrant_country": rdap_data.get("registrant_country"),
        "ip": (ips[0] if ips else None),
        "all_ips": ips,
        "asn": ip_info.get("asn"),
        "isp": ip_info.get("isp"),
        "org": ip_info.get("org"),
        "city": ip_info.get("city"),
        "hosting": ip_info.get("hosting"),
        "domain_age_days": age_days,
        "domain_age_text": humanize_age(age_days),
        "created_at_domain": rdap_data.get("created_at"),
        "expires_at": rdap_data.get("expires_at"),
        "updated_at_domain": rdap_data.get("updated_at"),
        "days_until_expiry": rdap_data.get("days_until_expiry"),
        "registry_status": rdap_data.get("status") or [],
        "nameservers": rdap_data.get("nameservers") or [],
        "dns": dns_data,
        "https_ok": bool(https_data.get("ok")),
        "https_status": https_data.get("status_code"),
        "https_final_url": https_data.get("final_url"),
        "tls": tls_data,
        "urlscan": urlscan_data,
        "risk_level": evaluation["risk_level"],
        "risk_score": evaluation["risk_score"],
        "risk_factors": evaluation["risk_factors"],
        "risk_summary": evaluation["risk_summary"],
        "errors": errors,
        "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    # Champs destinés uniquement à l'enregistrement en base (JSON Supabase)
    record["raw"] = {"rdap": rdap_data, "ip": ip_info, "https": https_data,
                     "dns": dns_data, "tls": tls_data}
    return record


def humanize_age(days: Optional[int]) -> str:
    """Traduit un nombre de jours en libellé lisible (« 3 ans et 2 mois »)."""
    # La valeur peut venir d'un gabarit Jinja où la clé est absente : on valide
    # le type plutôt que de supposer un entier.
    if not isinstance(days, (int, float)) or isinstance(days, bool):
        return "inconnu"
    days = int(days)
    if days < 0:
        return "date future incohérente"
    if days < 30:
        return f"{days} jour{'s' if days > 1 else ''}"
    if days < 365:
        months = days // 30
        return f"{months} mois"
    years, remainder = divmod(days, 365)
    months = remainder // 30
    text = f"{years} an{'s' if years > 1 else ''}"
    if months:
        text += f" et {months} mois"
    return text
