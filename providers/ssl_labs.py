"""
providers/ssl_labs.py — Note de configuration TLS, par Qualys SSL Labs.

POURQUOI CETTE SOURCE, ET PAS SEULEMENT LE CERTIFICAT

L'analyse précédente lisait le certificat présenté (émetteur, dates) et
vérifiait que le navigateur l'acceptait. C'est nécessaire, mais insuffisant et
peu parlant : un site peut présenter un certificat valide tout en acceptant des
protocoles obsolètes, des suites de chiffrement cassées, ou en laissant fuiter
des informations. Ces défauts ne se voient pas dans le certificat.

Qualys SSL Labs est la référence du domaine : son test public est utilisé
depuis quinze ans par les administrateurs, les auditeurs et les autorités de
certification. Il attribue une note de A+ à F qui synthétise l'ensemble de la
configuration. C'est exactement le type de résultat qu'un utilisateur non
technicien peut interpréter sans explication.

L'API est gratuite et sans clé. Elle applique une limite de débit et demande
que les résultats soient mis en cache — d'où le paramètre maxAge ci-dessous,
qui réutilise une analyse de moins de 24 heures au lieu d'en relancer une.

UNE API ASYNCHRONE, ET CE QUE CELA IMPOSE

Contrairement aux autres sources, SSL Labs ne répond pas immédiatement : on
dépose une demande, puis on interroge jusqu'à ce que l'analyse soit terminée.
Sur un domaine déjà analysé, la réponse arrive en une à deux secondes. Sur un
domaine inconnu, il faut compter 30 à 90 secondes.

Un site web ne peut pas faire patienter un visiteur une minute et demie pour un
seul indicateur. L'attente est donc bornée (SSLLABS_MAX_WAIT). Au-delà, la fiche
indique honnêtement que la note n'était pas disponible, plutôt que d'afficher
une valeur inventée ou de bloquer la page.
"""
import logging
import time
from typing import Any, Dict, Optional

import requests

import config

logger = logging.getLogger(__name__)

# Interprétation des notes, destinée à l'affichage grand public.
NOTES = {
    "A+": ("excellent", "Configuration exemplaire, au-delà des exigences actuelles."),
    "A":  ("très bien", "Configuration solide et à jour."),
    "A-": ("bien", "Bonne configuration, un détail perfectible."),
    "B":  ("correct", "Configuration acceptable, mais des points à corriger."),
    "C":  ("insuffisant", "Faiblesses réelles : protocoles anciens ou suites fragiles."),
    "D":  ("mauvais", "Failles sérieuses dans la configuration du chiffrement."),
    "E":  ("très mauvais", "Configuration dangereuse, à corriger sans délai."),
    "F":  ("critique", "Le chiffrement est inopérant : le site est exposé."),
    "T":  ("non approuvé", "Certificat non reconnu par les autorités de certification."),
    "M":  ("nom différent", "Le certificat ne correspond pas au nom du domaine."),
}


class SslLabsError(RuntimeError):
    """SSL Labs n'a pas pu fournir de résultat exploitable."""


def _interpreter_note(note: Optional[str]) -> Dict[str, Any]:
    if not note:
        return {"note": None, "niveau": "inconnu", "explication": None}
    niveau, explication = NOTES.get(note.upper(), ("non classé", None))
    return {"note": note.upper(), "niveau": niveau, "explication": explication}


def _resume_endpoint(endpoint: Dict[str, Any]) -> Dict[str, Any]:
    """Extrait d'un point de terminaison les éléments utiles à la fiche."""
    details = endpoint.get("details") or {}
    protocoles = []
    for protocole in details.get("protocols") or []:
        nom = protocole.get("name") or ""
        version = protocole.get("version") or ""
        if nom:
            protocoles.append(f"{nom} {version}".strip())

    return {
        "adresse": endpoint.get("ipAddress"),
        "serveur": endpoint.get("serverName"),
        "note": endpoint.get("grade"),
        "note_sans_contournement": endpoint.get("gradeTrustIgnored"),
        "avertissements": bool(endpoint.get("hasWarnings")),
        "protocoles": sorted(set(protocoles)),
        # Renégociation non sécurisée : défaut ancien mais toujours rencontré.
        "renégociation_non_securisee": endpoint.get("renegSupport") == 1,
    }


def _analyser(domaine: str) -> Dict[str, Any]:
    """Dépose puis suit une analyse jusqu'à obtention du résultat."""
    parametres = {
        "host": domaine,
        "all": "done",
        # Réutilise une analyse de moins de 24 heures : c'est demandé par les
        # conditions d'usage, et cela évite de faire patienter inutilement.
        "maxAge": 24,
    }
    echeance = time.monotonic() + config.SSLLABS_MAX_WAIT
    attente = 5.0
    derniere_erreur = None

    while time.monotonic() < echeance:
        try:
            reponse = requests.get(
                config.SSLLABS_ENDPOINT,
                params=parametres,
                headers={"Accept": "application/json",
                         "User-Agent": config.USER_AGENT},
                timeout=config.HTTP_TIMEOUT,
            )
        except requests.RequestException as exc:
            derniere_erreur = f"{exc.__class__.__name__}"
            break

        if reponse.status_code in (429, 503):
            derniere_erreur = ("SSL Labs a refusé la requête (limite de débit "
                               f"atteinte, HTTP {reponse.status_code}).")
            break
        if reponse.status_code != 200:
            derniere_erreur = f"SSL Labs a répondu HTTP {reponse.status_code}."
            break

        try:
            donnees = reponse.json()
        except ValueError:
            derniere_erreur = "réponse illisible"
            break

        statut = str(donnees.get("status") or "").upper()

        if statut == "READY":
            return {"pret": True, "donnees": donnees}
        if statut in ("ERROR", "DNS"):
            message = donnees.get("statusMessage") or "échec de l'analyse"
            raise SslLabsError(f"SSL Labs n'a pas pu analyser ce domaine ({message}).")
        if statut == "IN_PROGRESS":
            # Premier appel : le test vient d'être déposé. On patiente.
            time.sleep(attente)
            attente = min(attente + 3, 12)     # intervalle progressif
            continue
        # Statut inconnu (ex. « DNS » transitoire) : on retente.
        time.sleep(3)

    if derniere_erreur:
        raise SslLabsError(derniere_erreur)
    raise SslLabsError(
        f"note non disponible dans le délai imparti ({int(config.SSLLABS_MAX_WAIT)} s).")


def evaluer(domaine: str) -> Dict[str, Any]:
    """
    Note TLS du domaine.

    Ne lève jamais : en cas d'échec ou de délai dépassé, « disponible » vaut
    False et « erreur » explique pourquoi. L'analyse du domaine se poursuit.
    """
    resultat: Dict[str, Any] = {
        "disponible": False,
        "source": "Qualys SSL Labs",
        "note": None, "niveau": "inconnu", "explication": None,
        "adresse": None, "serveur": None,
        "protocoles": [], "avertissements": False,
        "note_sans_contournement": None,
        "erreur": None,
    }
    if not config.SSLLABS_ENABLED:
        resultat["erreur"] = "source désactivée dans la configuration"
        return resultat

    try:
        analyse = _analyser(domaine)
    except SslLabsError as exc:
        resultat["erreur"] = str(exc)
        return resultat
    except Exception as exc:                                  # noqa: BLE001
        resultat["erreur"] = f"{type(exc).__name__}: {exc}"
        return resultat

    donnees = analyse["donnees"]
    endpoints = donnees.get("endpoints") or []
    if not endpoints:
        resultat["erreur"] = "aucun point de terminaison analysé"
        return resultat

    endpoints_resumes = [_resume_endpoint(e) for e in endpoints]
    principal = endpoints_resumes[0]

    # La note affichée est la plus faible des points de terminaison : si un
    # serveur du domaine est mal configuré, la fiche ne doit pas s'abriter
    # derrière les autres.
    notes = [e["note"] for e in endpoints_resumes if e.get("note")]
    note_retenue = _note_la_plus_faible(notes) or principal["note"]

    resultat.update({
        "disponible": True,
        **_interpreter_note(note_retenue),
        "adresse": principal["adresse"],
        "serveur": principal["serveur"],
        "protocoles": sorted({p for e in endpoints_resumes for p in e["protocoles"]}),
        "avertissements": any(e["avertissements"] for e in endpoints_resumes),
        "note_sans_contournement": principal["note_sans_contournement"],
        "points_de_terminaison": len(endpoints_resumes),
    })
    return resultat


def _note_la_plus_faible(notes: list) -> Optional[str]:
    """Retient la note la plus basse parmi celles obtenues (« A+ » > « A » > …)."""
    if not notes:
        return None
    ordre = ["A+", "A", "A-", "B", "C", "D", "E", "F", "T", "M"]
    rang = {n: i for i, n in enumerate(ordre)}
    # Une note inconnue est ignorée plutôt que traitée comme la pire.
    connues = [n for n in notes if n.upper() in rang]
    if not connues:
        return notes[0]
    return max(connues, key=lambda n: rang[n.upper()])
