"""
providers/ip_info.py — Qui possède une adresse IP, et où elle se trouve.

DEUX QUESTIONS DIFFÉRENTES, DEUX SOURCES DIFFÉRENTES

C'est la distinction centrale de ce module, et la raison pour laquelle il
interroge deux services au lieu d'un :

  * « À qui cette adresse appartient-elle ? » — c'est un FAIT DE REGISTRE.
    Réponse par RDAP, le protocole officiel des cinq registres régionaux
    (ARIN, RIPE, APNIC, LACNIC, AFRINIC). La réponse est juridique : elle
    nomme l'organisation à laquelle le bloc d'adresses a été attribué.

  * « Où se trouve la machine qui répond ? » — c'est une ESTIMATION.
    Réponse par IPinfo, à partir de bases commerciales. Elle peut se tromper :
    une adresse appartenant à un opérateur africain peut être localisée dans
    un centre de données européen, ce qui est exact — la machine y est — mais
    ne dit rien du siège de l'organisation.

Confondre les deux produit des fiches fausses : annoncer « ce site est
américain » parce que l'adresse est géolocalisée aux États-Unis, alors que le
registre attribue le bloc à une société ivoirienne, est une erreur de
raisonnement. Les deux informations sont donc collectées et présentées
séparément.

POURQUOI IP-API.COM A ÉTÉ ABANDONNÉ

L'ancien fournisseur n'était accessible qu'en HTTP sur son offre gratuite :
la requête circulait en clair, et rien n'empêchait un intermédiaire de
répondre à sa place. Sa précision de localisation est également inférieure à
celle des bases professionnelles, et il ne fournit aucune donnée de registre.

Aucune clé n'est nécessaire. Le jeton IPinfo, facultatif, débloque les
données de ville et de confidentialité (voir .env.example).
"""
import logging
import re
from typing import Any, Dict, Optional

import requests

import config

logger = logging.getLogger(__name__)

# Fournisseurs d'infrastructure : savoir qu'une adresse appartient à un de ces
# réseaux indique un hébergement professionnel, par opposition à une machine
# chez un particulier. C'est une INDICATION, pas une preuve, et elle est
# présentée comme telle dans l'interface.
INFRASTRUCTURES_CONNUES = (
    "amazon", "aws", "google", "microsoft", "azure", "cloudflare", "ovh",
    "digitalocean", "hetzner", "linode", "akamai", "fastly", "oracle",
    "alibaba", "tencent", "scaleway", "godaddy", "hostinger", "ionos",
    "contabo", "vultr", "leaseweb", "equinix", "netlify", "vercel",
)

# Opérateurs télécoms : à l'inverse, une adresse issue d'un réseau d'accès
# grand public suggère une connexion résidentielle ou mobile.
OPERATEURS_ACCES = (
    "orange", "mtn", "airtel", "vodafone", "sfr", "bouygues", "free sas",
    "telecom", "telefonica", "t-mobile", "verizon", "comcast", "africell",
)

# Les registres régionaux apparaissent eux-mêmes comme titulaires de certains
# blocs, notamment ceux qu'ils se réservent pour leurs propres services.
#
# Cas observé : l'adresse 1.1.1.1 est déclarée au registre comme appartenant à
# « APNIC Research and Development » — le registre lui-même — alors que le
# service qui répond est celui de Cloudflare. Afficher « appartient à APNIC »
# est exact au sens juridique et trompeur pour un lecteur : il veut savoir qui
# exploite l'adresse, pas qui l'a allouée.
REGISTRES_REGIONAUX = (
    "apnic", "ripencc", "ripe ncc", "arin", "lacnic", "afrinic",
    "iana", "icann",
)


def _extraire_asn(texte: Optional[str]) -> Optional[str]:
    """Tire le numéro d'AS d'un libellé IPinfo du type « AS15169 Google LLC »."""
    if not texte:
        return None
    trouve = re.match(r"^(AS\d+)\s", str(texte))
    return trouve.group(1) if trouve else None


def _extraire_organisation(texte: Optional[str]) -> Optional[str]:
    """Retire le préfixe AS du libellé IPinfo (« AS15169 Google LLC »)."""
    if not texte:
        return None
    return re.sub(r"^AS\d+\s+", "", str(texte)).strip() or None


def _rdap_ip(ip: str) -> Dict[str, Any]:
    """
    Propriétaire officiel du bloc d'adresses, d'après le registre régional.

    C'est la donnée qui fait autorité : elle est publiée par l'organisation qui
    gère réellement l'allocation, pas déduite d'une base commerciale.
    """
    resultat: Dict[str, Any] = {"disponible": False, "proprietaire": None,
                                "bloc": None, "type": None, "erreur": None}
    try:
        reponse = requests.get(
            f"{config.RDAP_ENDPOINT.rsplit('/domain', 1)[0]}/ip/{ip}",
            headers={"Accept": "application/rdap+json",
                     "User-Agent": config.USER_AGENT},
            timeout=config.HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        resultat["erreur"] = f"{exc.__class__.__name__}"
        return resultat

    if reponse.status_code != 200:
        resultat["erreur"] = f"HTTP {reponse.status_code}"
        return resultat

    try:
        donnees = reponse.json()
    except ValueError:
        resultat["erreur"] = "réponse illisible"
        return resultat

    # Le titulaire figure dans les entités de rôle « registrant ».
    proprietaire = None
    for entite in donnees.get("entities") or []:
        if "registrant" in (entite.get("roles") or []):
            vcard = entite.get("vcardArray")
            if vcard and len(vcard) >= 2:
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        proprietaire = str(item[3])
                        break
        if proprietaire:
            break

    debut, fin = donnees.get("startAddress"), donnees.get("endAddress")
    resultat.update({
        "disponible": True,
        "proprietaire": proprietaire or donnees.get("name"),
        "bloc": f"{debut} – {fin}" if debut and fin else None,
        "type": donnees.get("type"),
        "registre": donnees.get("port43") or donnees.get("handle"),
    })
    return resultat


def _ipinfo(ip: str) -> Dict[str, Any]:
    """
    Localisation estimée et opérateur, d'après IPinfo.

    Le jeton est facultatif : sans lui, l'offre gratuite répond la ville, la
    région, le pays et l'organisation. Avec lui s'ajoutent les indicateurs de
    confidentialité (VPN, proxy, hébergement).
    """
    resultat: Dict[str, Any] = {"disponible": False, "erreur": None}
    parametres = {}
    if config.IPINFO_TOKEN:
        parametres["token"] = config.IPINFO_TOKEN

    try:
        reponse = requests.get(
            config.IPINFO_ENDPOINT.format(ip=ip),
            params=parametres or None,
            headers={"Accept": "application/json",
                     "User-Agent": config.USER_AGENT},
            timeout=config.HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        resultat["erreur"] = f"{exc.__class__.__name__}"
        return resultat

    if reponse.status_code == 429:
        resultat["erreur"] = "quota IPinfo atteint"
        return resultat
    if reponse.status_code != 200:
        resultat["erreur"] = f"HTTP {reponse.status_code}"
        return resultat

    try:
        donnees = reponse.json()
    except ValueError:
        resultat["erreur"] = "réponse illisible"
        return resultat

    # Le champ « bogon » signale une adresse privée ou réservée : elle
    # n'appartient à personne et n'est pas localisable.
    if donnees.get("bogon"):
        resultat.update({"disponible": True, "privee": True})
        return resultat

    organisation = _extraire_organisation(donnees.get("org"))
    resultat.update({
        "disponible": True,
        "privee": False,
        "ville": donnees.get("city"),
        "region": donnees.get("region"),
        "pays": donnees.get("country"),
        "organisation": organisation,
        "asn": donnees.get("asn", {}).get("asn") if isinstance(donnees.get("asn"), dict)
               else _extraire_asn(donnees.get("org")),
        "coordonnees": donnees.get("loc"),
        "fuseau": donnees.get("timezone"),
    })

    # Champs présents uniquement avec un jeton payant ou un quota supérieur.
    confidentialite = donnees.get("privacy") or {}
    if confidentialite:
        resultat["vpn_ou_proxy"] = bool(confidentialite.get("vpn")
                                        or confidentialite.get("proxy"))
        resultat["hebergement"] = bool(confidentialite.get("hosting"))
    return resultat


def _est_un_registre(nom: Optional[str]) -> bool:
    """Vrai si le nom désigne un registre régional plutôt qu'un exploitant."""
    if not nom:
        return False
    minuscule = nom.lower()
    return any(r in minuscule for r in REGISTRES_REGIONAUX)


def _qualifier_operateur(*noms: Optional[str]) -> Dict[str, Any]:
    """
    Classe l'opérateur : hébergeur professionnel ou accès grand public.

    Plusieurs noms sont examinés, et le premier qui correspond à une catégorie
    connue l'emporte. Nécessaire parce que la source la plus autoritaire n'est
    pas toujours la plus précise : pour 1.1.1.1, le registre annonce APNIC et
    IPinfo annonce Cloudflare. Le second est la bonne réponse du point de vue
    de l'utilisateur, et il doit être trouvé même s'il vient en second.

    INDICATION, PAS CONCLUSION. Le classement repose sur le nom de
    l'organisation, ce qui suffit à orienter un lecteur non technique mais ne
    remplace pas une vérification.
    """
    noms_valides = [n.lower() for n in noms if n]
    if not noms_valides:
        return {"categorie": "inconnue", "libelle": "opérateur non identifié"}
    for nom in noms_valides:
        if any(m in nom for m in INFRASTRUCTURES_CONNUES):
            return {"categorie": "hebergement",
                    "libelle": "hébergeur professionnel (centre de données)"}
    for nom in noms_valides:
        if any(m in nom for m in OPERATEURS_ACCES):
            return {"categorie": "acces",
                    "libelle": "opérateur de réseau grand public"}
    return {"categorie": "autre", "libelle": "organisation tierce"}


def localiser(ip: str) -> Dict[str, Any]:
    """
    Fiche complète d'une adresse IP : propriétaire officiel, localisation, opérateur.

    Ne lève jamais : en cas d'échec des deux sources, les champs restent vides
    et « erreur » explique pourquoi. Une panne de fournisseur ne doit pas
    empêcher l'analyse du domaine.
    """
    resultat: Dict[str, Any] = {
        "ip": ip,
        "proprietaire": None,      # fait de registre — RDAP
        "proprietaire_du_bloc": None,   # renseigné si le registre se déclare titulaire
        "bloc": None,
        "pays": None,              # estimation — IPinfo
        "ville": None,
        "region": None,
        "organisation": None,
        "asn": None,
        "coordonnees": None,
        "operateur": {"categorie": "inconnue", "libelle": "non déterminé"},
        "vpn_ou_proxy": None,
        "hebergement": None,
        "sources": [],
        "erreur": None,
    }

    rdap = _rdap_ip(ip)
    infos = _ipinfo(ip)

    if rdap.get("disponible"):
        resultat["proprietaire"] = rdap["proprietaire"]
        resultat["bloc"] = rdap["bloc"]
        resultat["sources"].append("Registre régional (RDAP)")
    if infos.get("disponible") and not infos.get("privee"):
        resultat["pays"] = infos.get("pays")
        resultat["ville"] = infos.get("ville")
        resultat["region"] = infos.get("region")
        resultat["organisation"] = infos.get("organisation")
        resultat["asn"] = infos.get("asn")
        resultat["coordonnees"] = infos.get("coordonnees")
        resultat["vpn_ou_proxy"] = infos.get("vpn_ou_proxy")
        resultat["hebergement"] = infos.get("hebergement")
        resultat["sources"].append("IPinfo")

    # Quand le registre se déclare lui-même titulaire du bloc, ce n'est pas
    # l'information utile : on lui préfère l'organisation relevée par IPinfo,
    # qui désigne l'exploitant réel. Le fait de registre reste conservé dans
    # « bloc » et « sources ».
    if _est_un_registre(resultat["proprietaire"]) and resultat["organisation"]:
        resultat["proprietaire_du_bloc"] = resultat["proprietaire"]
        resultat["proprietaire"] = resultat["organisation"]

    # Le classement examine les deux noms : la source autoritaire en premier,
    # puis la plus précise.
    resultat["operateur"] = _qualifier_operateur(
        resultat["proprietaire"], resultat["organisation"])

    if not resultat["sources"]:
        resultat["erreur"] = (rdap.get("erreur") or infos.get("erreur")
                              or "aucune source disponible")
    return resultat
