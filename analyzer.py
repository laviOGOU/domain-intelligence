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

import explications
import risk
from providers import (cert_transparency, dns_doh, ip_info, network, rdap,
                       ssl_labs, urlscan, virus_total)

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


def _resoudre_et_localiser(domaine: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Résolution DNS par résolveurs publics, puis localisation de la première adresse.

    Deux étapes enchaînées : la localisation a besoin d'une adresse, elle ne
    peut donc pas être lancée en parallèle de la résolution.
    """
    resolution = dns_doh.resoudre(domaine)
    adresses = resolution.get("ipv4") or resolution.get("ipv6") or []
    localisation: Dict[str, Any] = {}
    if adresses:
        localisation = ip_info.localiser(adresses[0])
    return resolution, localisation


def analyze(domain: str) -> Dict[str, Any]:
    """
    Analyse complète d'un domaine et retourne la fiche prête à afficher.

    Ne lève jamais pour un simple échec réseau : les erreurs sont consignées dans
    le champ 'errors' de chaque section, la fiche reste consultable.

    Les sources interrogées, et ce que chacune apporte :

      RDAP (ICANN)          qui a enregistré le domaine, quand, jusqu'à quand
      Cloudflare + Google   adresses réelles, d'après deux résolveurs publics
      RDAP/IP + IPinfo      propriétaire officiel du bloc, puis localisation
      Qualys SSL Labs       note de A+ à F sur la configuration du chiffrement
      VirusTotal            verdict de plus de 70 moteurs de sécurité
      crt.sh                sous-domaines révélés par les journaux publics
      urlscan.io            hébergeur et réputation observés sur le terrain

    Chaque source est indépendante : si l'une échoue, les autres répondent
    toujours et la fiche indique ce qui manque, plutôt que de tout annuler.
    """
    domain = normalize_domain(domain)
    tld = get_tld(domain)
    errors: List[str] = []

    rdap_data: Dict[str, Any] = {}
    registered = True
    rdap_available = True

    with ThreadPoolExecutor(max_workers=9) as pool:
        future_rdap = pool.submit(rdap.lookup, domain)
        future_dns = pool.submit(dns_doh.enregistrements, domain)
        future_resolution = pool.submit(_resoudre_et_localiser, domain)
        future_https = pool.submit(network.check_https, domain)
        future_tls = pool.submit(network.tls_certificate, domain)
        future_urlscan = pool.submit(urlscan.lookup, domain)
        future_ssl = pool.submit(ssl_labs.evaluer, domain)
        future_vt = pool.submit(virus_total.reputation, domain)
        future_ct = pool.submit(cert_transparency.sous_domaines, domain)

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
        except Exception:                              # noqa: BLE001
            logger.exception("Erreur inattendue DNS")
            dns_data = {"ns": [], "mx": [], "txt": [], "erreur": "Erreur de collecte"}
            errors.append("DNS : erreur de collecte")

        try:
            resolution, ip_info_data = future_resolution.result()
            ips = resolution.get("ipv4") or []
        except Exception:                              # noqa: BLE001
            logger.exception("Erreur inattendue résolution DNS")
            resolution, ip_info_data, ips = {}, {}, []
            errors.append("Résolution DNS : erreur de collecte")
        if resolution.get("erreur"):
            errors.append(f"Résolution DNS : {resolution['erreur']}")
        if resolution.get("divergence"):
            errors.append(f"Résolution DNS : {resolution['divergence']}")

        try:
            https_data = future_https.result()
        except Exception:                              # noqa: BLE001
            logger.exception("Erreur inattendue HTTPS")
            https_data = {"ok": False, "status_code": None, "final_url": None,
                          "redirects_to_other_host": False, "error": "Erreur de vérification"}
            errors.append("HTTPS : erreur de vérification")

        try:
            tls_data = future_tls.result()
        except Exception:                              # noqa: BLE001
            logger.exception("Erreur inattendue TLS")
            tls_data = {"error": "Erreur de collecte"}
            errors.append("TLS : erreur de collecte")

        try:
            urlscan_data = future_urlscan.result()
        except urlscan.UrlscanError as exc:
            # API externe indisponible ou quota atteint : limite signalée, pas
            # de pénalité (voir risk.evaluate).
            urlscan_data = {"available": False, "source": "urlscan.io", "error": str(exc)}
            errors.append(f"urlscan.io : {exc}")
        except Exception:                              # noqa: BLE001
            logger.exception("Erreur inattendue urlscan.io")
            urlscan_data = {"available": False, "source": "urlscan.io",
                            "error": "Erreur de collecte"}
            errors.append("urlscan.io : erreur de collecte")

        try:
            ssl_data = future_ssl.result()
        except Exception:                              # noqa: BLE001
            logger.exception("Erreur inattendue SSL Labs")
            ssl_data = {"disponible": False, "source": "Qualys SSL Labs",
                        "erreur": "Erreur de collecte"}
        if not ssl_data.get("disponible") and ssl_data.get("erreur") \
                and "désactivée" not in str(ssl_data["erreur"]):
            errors.append(f"SSL Labs : {ssl_data['erreur']}")

        try:
            vt_data = future_vt.result()
        except Exception:                              # noqa: BLE001
            logger.exception("Erreur inattendue VirusTotal")
            vt_data = {"disponible": False, "source": "VirusTotal",
                       "erreur": "Erreur de collecte"}

        try:
            ct_data = future_ct.result()
        except Exception:                              # noqa: BLE001
            logger.exception("Erreur inattendue journaux de certificats")
            ct_data = {"disponible": False,
                       "source": "Journaux de transparence des certificats (crt.sh)",
                       "erreur": "Erreur de collecte"}
        if not ct_data.get("disponible") and ct_data.get("erreur") \
                and "désactivée" not in str(ct_data["erreur"]):
            errors.append(f"Journaux de certificats : {ct_data['erreur']}")

    if not registered:
        rdap_data = {"registrar": None, "age_days": None, "status": [],
                     "nameservers": [], "source": "RDAP (non enregistré)"}

    # Les informations de résolution qui portent un sens pour l'analyse sont
    # replacées dans le bloc DNS : « divergence » signale un désaccord entre
    # résolveurs sur l'EXISTENCE du nom (propagation anormale ou filtrage). Le
    # simple écart d'adresses entre résolveurs, lui, est normal pour tout site
    # réparti sur plusieurs serveurs et n'est donc pas un signal.
    dns_pour_analyse = dict(dns_data)
    dns_pour_analyse["divergence"] = resolution.get("divergence")
    dns_pour_analyse["existe"] = resolution.get("existe")
    dns_pour_analyse["adresses_divergent"] = resolution.get("adresses_divergent")

    payload = {
        "domain": domain,
        "tld": tld,
        "rdap": rdap_data,
        "ip": ip_info_data,
        "https": https_data,
        "dns": dns_pour_analyse,
        "resolution": resolution,
        "urlscan": urlscan_data,
        "ssl_labs": ssl_data,
        "virus_total": vt_data,
        "cert_transparency": ct_data,
        "registered": registered,
        "rdap_available": rdap_available,
    }
    evaluation = risk.evaluate(payload)
    # La synthèse en langage courant est construite après le score : elle
    # s'appuie sur les mêmes données, mais les présente pour un lecteur qui
    # n'est pas informaticien.
    #
    # Le niveau technique lui est transmis explicitement. Sans cela, la
    # fonction ne le trouvait pas dans les données et concluait « vérification
    # incomplète » sur des domaines parfaitement analysés — github.com, avec
    # trois signes favorables, aucun défavorable et un score de 0, était
    # annoncé comme non vérifié.
    synthese = explications.resume({
        **payload,
        "risk_level": evaluation["risk_level"],
        "risk_score": evaluation["risk_score"],
    })

    # Le pays affiché est celui de l'hébergement (le plus parlant), avec repli
    # sur le pays du registrar puis du titulaire.
    country = (ip_info_data.get("pays") or rdap_data.get("registrar_country")
               or rdap_data.get("registrant_country"))

    age_days = rdap_data.get("age_days")
    record: Dict[str, Any] = {
        "domain": domain,
        "tld": tld,
        "registered": registered,
        "registrar": rdap_data.get("registrar"),
        "registrar_id": rdap_data.get("registrar_id"),
        "country": country,
        "country_code": ip_info_data.get("pays") or None,
        "registrar_country": rdap_data.get("registrar_country"),
        "registrant_country": rdap_data.get("registrant_country"),
        "ip": (ips[0] if ips else None),
        "all_ips": resolution.get("ipv4", []) + resolution.get("ipv6", []),
        "asn": ip_info_data.get("asn"),
        "isp": ip_info_data.get("organisation"),
        "org": ip_info_data.get("proprietaire") or ip_info_data.get("organisation"),
        "city": ip_info_data.get("ville"),
        "hosting": ip_info_