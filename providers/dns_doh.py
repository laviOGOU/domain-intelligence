"""
providers/dns_doh.py — Résolution DNS par des résolveurs publics reconnus.

POURQUOI CE MODULE REMPLACE LE RÉSOLVEUR SYSTÈME

La version précédente interrogeait le résolveur du système d'exploitation
(socket.getaddrinfo et dnspython sans configuration de serveur). Trois défauts
en découlent, tous vérifiables :

  1. Le résultat dépend de la machine qui exécute l'analyse. Un même domaine
     analysé depuis Abidjan et depuis Paris peut donner des adresses
     différentes, sans qu'aucune des deux réponses ne soit fausse. Une fiche
     d'analyse n'est alors pas reproductible.

  2. Le résolveur du fournisseur d'accès peut filtrer, rediriger ou mettre en
     cache très longtemps. Dans plusieurs pays, les résolveurs locaux répondent
     volontairement une adresse de blocage : l'analyse décrirait alors la
     censure, pas le domaine.

  3. Le résultat n'est pas vérifiable. Rien dans la fiche ne dit quel serveur a
     répondu, donc rien ne permet de contester ou de reproduire la mesure.

Les résolveurs publics interrogés ici sont ceux de Cloudflare (1.1.1.1) et de
Google (8.8.8.8), joints en HTTPS. Tous deux publient des chiffres d'audience
publics les plaçant parmi les plus utilisés au monde, et surtout : la requête
est chiffrée, donc le fournisseur d'accès ne peut ni la lire ni la modifier.

LES DEUX SONT INTERROGÉS, ET CROISÉS

Interroger deux résolveurs indépendants coûte une requête de plus et apporte
une information qu'un seul ne peut pas donner : la convergence. Deux résolveurs
qui répondent la même chose rendent la mesure fiable ; deux réponses
différentes signalent soit une propagation DNS en cours, soit une
manipulation. C'est un signal en soi, et il est remonté comme tel.

Aucune clé d'API n'est nécessaire.
"""
import logging
from typing import Any, Dict, List, Optional

import requests

import config

logger = logging.getLogger(__name__)

# Types d'enregistrements collectés, et ce qu'ils apprennent à l'utilisateur.
TYPES = {
    "NS": "serveurs de noms",
    "MX": "serveurs de messagerie",
    "TXT": "enregistrements de vérification",
    "CNAME": "alias",
}

# Code de réponse DNS -> signification. Le code 3 (NXDOMAIN) est un résultat,
# pas une panne : il signifie que le nom n'existe pas.
CODES = {
    0: "réponse valide",
    2: "erreur du serveur",
    3: "nom inexistant",
    5: "requête refusée",
}


class DnsError(RuntimeError):
    """Aucun résolveur public n'a pu répondre."""


def _interroger(serveur: str, nom: str, type_record: str,
                delai: float) -> Dict[str, Any]:
    """Interroge un résolveur DoH unique. Lève DnsError en cas d'échec."""
    try:
        reponse = requests.get(
            serveur,
            params={"name": nom, "type": type_record},
            headers={"Accept": "application/dns-json",
                     "User-Agent": config.USER_AGENT},
            timeout=delai,
        )
    except requests.RequestException as exc:
        raise DnsError(f"{exc.__class__.__name__}") from exc

    if reponse.status_code != 200:
        raise DnsError(f"HTTP {reponse.status_code}")

    try:
        charge = reponse.json()
    except ValueError as exc:
        raise DnsError("réponse illisible") from exc

    statut = charge.get("Status", 0)
    reponses = charge.get("Answer") or []
    return {
        "statut": statut,
        "statut_texte": CODES.get(statut, f"code {statut}"),
        # Le point final des noms DNS est retiré : « exemple.com. » se lit mal.
        "valeurs": [str(r.get("data", "")).rstrip(".") for r in reponses],
        "adresse_serveur": charge.get("Answer") and serveur or serveur,
    }


def interroger_les_deux(nom: str, type_record: str = "A",
                        delai: Optional[float] = None) -> Dict[str, Any]:
    """
    Interroge Cloudflare et Google, puis croise les deux réponses.

    Retourne toujours un dictionnaire exploitable. La clé « consensus » vaut
    True quand les deux résolveurs s'accordent, False quand ils divergent, et
    None quand un seul a répondu — auquel cas on ne peut rien conclure sur la
    convergence.
    """
    delai = delai or config.DNS_TIMEOUT
    resultats: Dict[str, Any] = {}
    erreurs: List[str] = []

    for etiquette, serveur in (("Cloudflare", config.DOH_CLOUDFLARE),
                               ("Google", config.DOH_GOOGLE)):
        try:
            resultats[etiquette] = _interroger(serveur, nom, type_record, delai)
        except DnsError as exc:
            erreurs.append(f"{etiquette} : {exc}")

    if not resultats:
        raise DnsError("aucun résolveur public joignable (" + " ; ".join(erreurs) + ")")

    jeux = [set(r["valeurs"]) for r in resultats.values()]
    consensus: Optional[bool] = None
    if len(jeux) == 2:
        consensus = jeux[0] == jeux[1]

    return {
        "nom": nom,
        "type": type_record,
        "resoluteurs": resultats,
        "erreurs": erreurs,
        "consensus": consensus,
        # On expose l'union : une adresse annoncée par un seul résolveur reste
        # une adresse réellement servie à une partie du web.
        "valeurs": sorted(set().union(*jeux)) if jeux else [],
    }


def resoudre(domaine: str) -> Dict[str, Any]:
    """
    Adresses IPv4 et IPv6 du domaine, vues par les résolveurs publics.

    Aucune exception n'est levée : en cas de panne complète, la clé « error »
    est renseignée et la fiche reste consultable.

    CE QUE L'ACCORD ENTRE RÉSOLVEURS SIGNIFIE, ET CE QU'IL NE SIGNIFIE PAS

    Première version de ce module : deux résolveurs annonçant des adresses
    différentes étaient traités comme un signal suspect. C'était faux.

    Google et GitHub, interrogés pendant la mise au point, renvoient l'un et
    l'autre des adresses différentes selon le résolveur. C'est le comportement
    normal de tout site réparti sur plusieurs serveurs (répartition de charge,
    réseau de diffusion) : le résolveur le plus proche reçoit les adresses du
    centre de données le plus proche. En faire une alerte revenait à signaler
    comme suspects exactement les sites les mieux infrastructurels.

    Le désaccord sur les ADRESSES est donc purement informatif : il est
    conservé pour l'affichage, jamais utilisé comme pénalité.

    Le seul désaccord réellement signifiant porte sur l'EXISTENCE : un
    résolveur qui répond « nom inexistant » quand l'autre renvoie des adresses
    révèle une propagation en cours ou un filtrage. C'est ce cas, et lui seul,
    qui est remonté comme « divergence ».
    """
    resultat: Dict[str, Any] = {
        "ipv4": [], "ipv6": [],
        "source": "Cloudflare 1.1.1.1 et Google 8.8.8.8, joints en HTTPS",
        "adresses_divergent": None,   # informatif : normal sur un site réparti
        "divergence": None,           # signifiant : désaccord sur l'existence
        "erreur": None, "existe": None,
    }

    for famille, cle in (("A", "ipv4"), ("AAAA", "ipv6")):
        try:
            reponse = interroger_les_deux(domaine, famille)
        except DnsError as exc:
            resultat["erreur"] = str(exc)
            continue

        resultat[cle] = reponse["valeurs"]
        if famille == "A":
            resultat["adresses_divergent"] = (reponse["consensus"] is False)

            # Existence : on ne conclut que si les deux résolveurs s'accordent.
            statuts = [r["statut"] for r in reponse["resoluteurs"].values()]
            if len(statuts) == 2:
                if all(s == 3 for s in statuts):
                    resultat["existe"] = False          # les deux : inexistant
                elif 3 in statuts:
                    resultat["existe"] = None           # désaccord : on ne conclut pas
                    resultat["divergence"] = (
                        "Un résolveur annonce ce nom inexistant, l'autre le "
                        "résout. Propagation en cours, ou filtrage sur l'un des "
                        "deux réseaux."
                    )
                else:
                    resultat["existe"] = True
            elif statuts:
                resultat["existe"] = None if statuts[0] == 3 else True

    if resultat["erreur"] and not resultat["ipv4"] and not resultat["ipv6"]:
        resultat["existe"] = None
    return resultat


def enregistrements(domaine: str) -> Dict[str, Any]:
    """
    NS, MX, TXT et CNAME du domaine, par résolveurs publics.

    Remplace l'ancienne collecte dnspython, qui interrogeait le résolveur du
    système et dépendait donc de la connexion de la machine.
    """
    resultat: Dict[str, Any] = {
        "ns": [], "mx": [], "txt": [], "cname": [],
        "source": "Cloudflare 1.1.1.1 et Google 8.8.8.8 (HTTPS)",
        "erreur": None, "types_obtenus": [],
    }
    for type_record, cle in (("NS", "ns"), ("MX", "mx"),
                             ("TXT", "txt"), ("CNAME", "cname")):
        try:
            reponse = interroger_les_deux(domaine, type_record)
        except DnsError:
            continue
        valeurs = reponse["valeurs"]
        if cle == "txt":
            # Les TXT contiennent souvent des chaînes très longues (clés de
            # vérification, SPF). On garde le début, suffisant à l'affichage.
            valeurs = [v[:300] for v in valeurs][:8]
        resultat[cle] = valeurs
        if valeurs:
            resultat["types_obtenus"].append(TYPES.get(type_record, type_record))

    if not resultat["types_obtenus"]:
        resultat["erreur"] = "aucun enregistrement obtenu"
    return resultat


def resoudre_depuis_plusieurs(domaine: str) -> Dict[str, Any]:
    """Résumé court, destiné à l'affichage : adresses, source et divergences."""
    a = resoudre(domaine)
    return {
        "adresses": a["ipv4"] + a["ipv6"],
        "adresses_divergent": a["adresses_divergent"],
        "divergence": a["divergence"],
        "source": a["source"],
        "erreur": a["erreur"],
    }
