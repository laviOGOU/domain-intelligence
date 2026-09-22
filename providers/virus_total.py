"""
providers/virus_total.py — Réputation du domaine, par VirusTotal.

VirusTotal est la référence mondiale de la réputation : la plateforme agrège le
verdict de plus de 70 moteurs antivirus et de dizaines de listes de blocage,
puis publie le décompte. C'est la source que consultent les équipes de sécurité
avant d'ouvrir un lien douteux.

POURQUOI CETTE SOURCE CHANGE LA FICHE

Les autres sources décrivent la forme du domaine : son âge, son hébergeur, sa
configuration. Aucune ne dit si le domaine est *connu pour être dangereux*.
C'est une information complètement différente, et c'est celle qui répond
directement à la question de l'utilisateur : « puis-je faire confiance à ce
site ? »

La réponse est aussi la plus lisible qui existe : « 3 moteurs sur 94 signalent
ce site comme malveillant ». Aucune compétence technique n'est requise.

CLÉ REQUISE, MAIS FACULTATIVE

VirusTotal exige un compte, gratuit, donnant droit à 4 requêtes par minute et
500 par jour. Le service est donc ignoré proprement si VIRUSTOTAL_KEY est
absente : la fiche perd une source, elle ne casse pas.

Cette limite de débit interdit d'en faire une source systématique pour un usage
intensif. Pour un outil d'analyse à la demande, elle est suffisante.
"""
import logging
from typing import Any, Dict, Optional

import requests

import config

logger = logging.getLogger(__name__)


class VirusTotalError(RuntimeError):
    """VirusTotal n'a pas pu être interrogé."""


def _interpreter(stats: Dict[str, Any]) -> Dict[str, Any]:
    """
    Traduit le décompte des moteurs en verdict lisible.

    Le seuil est volontairement bas : sur les plateformes de réputation, un
    signalement unique suffit souvent à écarter un domaine. Deux moteurs qui
    signalent le même domaine ont très rarement tort tous les deux.
    """
    malveillants = int(stats.get("malicious") or 0)
    suspects = int(stats.get("suspicious") or 0)
    inoffensifs = int(stats.get("harmless") or 0)
    non_detectes = int(stats.get("undetected") or 0)
    total = malveillants + suspects + inoffensifs + non_detectes

    signale = malveillants + suspects
    if malveillants >= 2:
        verdict, niveau = "signalé comme malveillant", "critique"
    elif malveillants == 1:
        verdict, niveau = "signalé par un moteur", "eleve"
    elif suspects >= 2:
        verdict, niveau = "comportement suspect signalé", "eleve"
    elif suspects == 1:
        verdict, niveau = "légèrement suspect", "moyen"
    else:
        verdict, niveau = "aucun signalement", "faible"

    return {
        "moteurs_total": total,
        "moteurs_malveillants": malveillants,
        "moteurs_suspects": suspects,
        "verdict": verdict,
        "niveau": niveau,
        # Phrase prête à afficher, écrite ici pour rester cohérente avec le
        # décompte qu'elle commente.
        "phrase": (f"{signale} moteur{'s' if signale > 1 else ''} sur {total} "
                   f"signale{'nt' if signale > 1 else ''} ce site."
                   if signale else
                   f"Aucun des {total} moteurs ne signale ce site."),
    }


def reputation(domaine: str) -> Dict[str, Any]:
    """
    Verdict des moteurs de VirusTotal sur le domaine.

    Ne lève jamais : sans clé, ou en cas d'échec, « disponible » vaut False et
    « erreur » explique pourquoi.
    """
    resultat: Dict[str, Any] = {
        "disponible": False,
        "source": "VirusTotal",
        "verdict": None, "niveau": None, "phrase": None,
        "moteurs_total": None, "moteurs_malveillants": None, "moteurs_suspects": None,
        "categories": [], "reputation": None,
        "erreur": None,
    }

    if not config.VIRUSTOTAL_KEY:
        resultat["erreur"] = ("clé absente — ajoutez VIRUSTOTAL_KEY dans .env "
                              "(compte gratuit) pour activer cette source")
        return resultat

    try:
        reponse = requests.get(
            config.VIRUSTOTAL_ENDPOINT.format(domain=domaine),
            headers={"x-apikey": config.VIRUSTOTAL_KEY,
                     "Accept": "application/json",
                     "User-Agent": config.USER_AGENT},
            timeout=config.HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        resultat["erreur"] = f"{exc.__class__.__name__}"
        return resultat

    if reponse.status_code == 401:
        resultat["erreur"] = "clé refusée par VirusTotal (vérifiez VIRUSTOTAL_KEY)"
        return resultat
    if reponse.status_code == 429:
        resultat["erreur"] = ("quota VirusTotal atteint (4 requêtes/minute, "
                              "500/jour sur l'offre gratuite)")
        return resultat
    if reponse.status_code == 404:
        # Domaine inconnu de VirusTotal : ce n'est pas une erreur, c'est une
        # absence d'historique. À dire tel quel.
        resultat.update({"disponible": True, "verdict": "jamais analysé",
                         "niveau": "inconnu",
                         "phrase": "VirusTotal n'a encore jamais analysé ce domaine."})
        return resultat
    if reponse.status_code != 200:
        resultat["erreur"] = f"HTTP {reponse.status_code}"
        return resultat

    try:
        donnees = (reponse.json() or {}).get("data") or {}
    except ValueError:
        resultat["erreur"] = "réponse illisible"
        return resultat

    attributs = donnees.get("attributes") or {}
    stats = attributs.get("last_analysis_stats") or {}
    interpretation = _interpreter(stats)

    categories = attributs.get("categories") or {}
    resultat.update({
        "disponible": True,
        **interpretation,
        # Les catégories disent *comment* le domaine est classé (phishing,
        # malware, forum...). Plus parlant qu'un simple chiffre.
        "categories": sorted({str(v) for v in categories.values()})[:6],
        "reputation": attributs.get("reputation"),
        "derniere_analyse": attributs.get("last_analysis_date"),
    })
    return resultat
