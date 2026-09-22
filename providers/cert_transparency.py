"""
providers/cert_transparency.py — Sous-domaines révélés par les journaux de certificats.

PRINCIPE

Depuis 2018, toute autorité de certification doit inscrire publiquement chaque
certificat qu'elle délivre dans des journaux de transparence (Certificate
Transparency), conformément au standard RFC 6962. Ces journaux sont publics,
permanents et impossibles à modifier a posteriori.

Conséquence pratique : chaque certificat émis pour un domaine y est inscrit,
avec la liste des noms qu'il couvre. On obtient ainsi les sous-domaines
réellement utilisés — y compris ceux qu'aucune page ne mentionne, qu'aucun moteur
de recherche n'indexe, et qui ne répondent pas forcément au grand public :
portails d'administration, environnements de test, serveurs de messagerie.

C'est une méthode de reconnaissance standard, enseignée dans les référentiels
d'audit (OWASP, PTES), et utilisée quotidiennement par les équipes de sécurité.

POURQUOI C'EST UTILE À UN UTILISATEUR NON TECHNIQUE

Un domaine d'apparence anodine peut révéler des dizaines de sous-domaines dont
certains trahissent sa nature : « test- », « dev- », « admin- », ou à l'inverse
une infrastructure cohérente et professionnelle. C'est un indicateur de maturité
et de sérieux, et il se lit sans compétence particulière.

crt.sh est le moteur de recherche public de référence sur ces journaux. Gratuit,
sans clé. Le service est parfois lent et peut renvoyer une erreur : c'est
accepté comme un échec ordinaire, pas comme une panne de l'outil.
"""
import logging
import re
import time
from typing import Any, Dict, List, Optional

import requests

import config

logger = logging.getLogger(__name__)

# Préfixes qui trahissent un environnement qui n'était pas destiné au public.
PREFIXES_SENSIBLES = {
    "admin": "administration",
    "administrator": "administration",
    "test": "environnement de test",
    "dev": "développement",
    "staging": "préproduction",
    "preprod": "préproduction",
    "demo": "démonstration",
    "beta": "version bêta",
    "internal": "réseau interne",
    "intranet": "réseau interne",
    "vpn": "accès distant",
    "mail": "messagerie",
    "smtp": "messagerie",
    "imap": "messagerie",
    "ftp": "transfert de fichiers",
    "db": "base de données",
    "database": "base de données",
    "backup": "sauvegardes",
    "old": "ancienne version",
    "legacy": "ancienne version",
    "jenkins": "intégration continue",
    "git": "dépôt de code",
    "gitlab": "dépôt de code",
    "phpmyadmin": "administration de base de données",
    "webmail": "messagerie",
    "cpanel": "administration d'hébergement",
    "monitoring": "supervision",
    "grafana": "supervision",
    "kibana": "supervision",
}

# Nombre de sous-domaines conservés : au-delà, l'information se répète et la
# fiche devient illisible.
LIMITE_SOUS_DOMAINES = 40


class CrtshError(RuntimeError):
    """crt.sh n'a pas pu être interrogé."""


def _nettoyer_noms(bruts: List[str], domaine: str) -> List[str]:
    """
    Normalise et filtre les noms renvoyés par crt.sh.

    Les journaux contiennent des caractères d'échappement et des doublons : un
    même nom apparaît pour chaque certificat qui le couvre, soit parfois des
    dizaines de fois.
    """
    trouves = set()
    for brut in bruts:
        for nom in str(brut).split("\n"):
            nom = nom.strip().lower().rstrip(".")
            # Les journaux utilisent « *.exemple.com » pour les certificats
            # génériques, et échappent parfois le point.
            nom = nom.replace("*.", "").replace("\\.", ".")
            if not nom or "@" in nom:
                continue
            # On ne garde que ce qui appartient réellement au domaine analysé.
            if nom == domaine or nom.endswith("." + domaine):
                trouves.add(nom)
    return sorted(trouves)


def _interroger_crtsh(domaine: str) -> list:
    """
    Interroge crt.sh avec réessais.

    crt.sh est un service gratuit régulièrement surchargé : sur trois essais
    consécutifs pendant la mise au point, deux ont renvoyé « HTTP 502 Bad
    Gateway » et le troisième a répondu normalement. Sans réessai, la source
    aurait été indisponible environ deux fois sur trois, ce qui aurait fait
    passer une panne d'infrastructure pour une absence de données.

    La requête n'utilise PAS le joker « %.domaine », pourtant courant dans les
    exemples. Ce joker alourdit la recherche côté serveur et multiplie les
    erreurs 502 ; la forme simple renvoie les mêmes sous-domaines, vérifié sur
    github.com (139 sous-domaines obtenus).
    """
    derniere_erreur = "aucune tentative"
    for tentative in range(3):
        try:
            reponse = requests.get(
                config.CRTSH_ENDPOINT,
                params={"q": domaine, "output": "json"},
                headers={"User-Agent": config.USER_AGENT,
                         "Accept": "application/json"},
                timeout=max(config.HTTP_TIMEOUT, 30),
            )
        except requests.RequestException as exc:
            derniere_erreur = f"crt.sh injoignable ({exc.__class__.__name__})"
            time.sleep(2 + tentative * 2)
            continue

        if reponse.status_code == 200:
            try:
                donnees = reponse.json()
            except ValueError:
                derniere_erreur = ("crt.sh n'a pas renvoyé de données exploitables "
                                   "(service surchargé)")
                time.sleep(2 + tentative * 2)
                continue
            if isinstance(donnees, list):
                return donnees
            derniere_erreur = "format de réponse inattendu"
            break

        derniere_erreur = f"crt.sh a répondu HTTP {reponse.status_code}"
        time.sleep(2 + tentative * 2)

    raise CrtshError(derniere_erreur)


def sous_domaines(domaine: str) -> Dict[str, Any]:
    """
    Sous-domaines du domaine, d'après les journaux publics de certificats.

    Ne lève jamais : en cas d'échec, « disponible » vaut False et « erreur »
    explique pourquoi.
    """
    resultat: Dict[str, Any] = {
        "disponible": False,
        "source": "Journaux de transparence des certificats (crt.sh)",
        "sous_domaines": [],
        "nombre": 0,
        "tronque": False,
        "environnements_exposes": [],
        "erreur": None,
    }
    if not config.CRTSH_ENABLED:
        resultat["erreur"] = "source désactivée dans la configuration"
        return resultat

    try:
        entrees = _interroger_crtsh(domaine)
    except CrtshError as exc:
        resultat["erreur"] = str(exc)
        return resultat

    bruts = [entree.get("name_value") for entree in entrees
             if isinstance(entree, dict) and entree.get("name_value")]
    noms = _nettoyer_noms(bruts, domaine)

    resultat["tronque"] = len(noms) > LIMITE_SOUS_DOMAINES
    resultat["sous_domaines"] = noms[:LIMITE_SOUS_DOMAINES]
    resultat["nombre"] = len(noms)
    resultat["disponible"] = True

    # Repérage des environnements qui n'étaient pas destinés au public.
    exposes = []
    for nom in noms:
        etiquette = nom.split(".")[0]
        for prefixe, description in PREFIXES_SENSIBLES.items():
            if etiquette == prefixe or etiquette.startswith(prefixe + "-") \
                    or etiquette.endswith("-" + prefixe):
                exposes.append({"nom": nom, "type": description})
                break
    resultat["environnements_exposes"] = exposes[:10]
    return resultat
