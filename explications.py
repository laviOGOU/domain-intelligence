"""
explications.py — Traduction d'une analyse technique en langage courant.

LE PROBLÈME QUE CE MODULE RÉSOUT

Une fiche d'analyse telle qu'elle était produite parlait de « score de risque »,
de « RDAP », de « réponse HTTP 403 » et d'« API urlscan.io ». Tout cela est
exact et n'est compréhensible que par quelqu'un dont c'est le métier.

Or la personne qui a besoin de cette analyse est rarement celle-là. Elle a reçu
un lien par message, elle se demande si elle peut ouvrir un compte, saisir son
numéro de carte ou cliquer. Elle n'a pas besoin de connaître le protocole TLS :
elle a besoin de savoir si c'est dangereux, et quoi faire.

CE QUE CE MODULE PRODUIT

  * une conclusion en une phrase, sans terme technique ;
  * ce qu'il faut faire concrètement ;
  * les signes favorables et défavorables, reformulés en français courant ;
  * les points qu'on n'a PAS pu vérifier, dits honnêtement.

PRINCIPE DE RÉDACTION : ne jamais rassurer à tort.

Un domaine ancien, bien configuré et jamais signalé reste un domaine dont on ne
connaît pas le propriétaire. La conclusion doit le dire, sans jargon et sans
fausse assurance. Une phrase rassurante à tort cause un préjudice réel ; une
phrase prudente coûte une hésitation.
"""
from typing import Any, Dict, List, Optional

# Niveaux, du plus rassurant au plus alarmant. « indéterminé » existe parce
# qu'une analyse dont les sources ont échoué ne doit pas être présentée comme
# rassurante.
NIVEAUX = ("favorable", "attention", "defavorable", "critique", "indetermine")

COULEURS = {
    "favorable": "vert",
    "attention": "orange",
    "defavorable": "rouge",
    "critique": "rouge",
    "indetermine": "gris",
}


def _verdict(niveau: str, domaine: str,
             signes: Optional[List[Dict[str, str]]] = None) -> Dict[str, str]:
    """
    Phrase de conclusion, et conseil pratique associé.

    La phrase est construite à partir du motif réellement relevé, et non d'une
    formule générique. La première version annonçait, pour tout cas critique,
    que « plusieurs sources signalent ce site comme dangereux » : appliqué à un
    domaine inexistant, c'était une affirmation fabriquée, puisqu'aucune source
    ne signale quoi que ce soit — le domaine n'existe pas.
    """
    signes = signes or []
    nombre = len(signes)

    if niveau == "critique":
        critique = next((s for s in signes if s.get("gravite") == "critique"), None)
        texte_critique = (critique or {}).get("texte", "")
        if "n'est enregistré par personne" in texte_critique:
            constat = (f"L'adresse {domaine} ne correspond à aucun site : ce "
                       "domaine n'est enregistré par personne. Un message qui "
                       "porte ce lien est nécessairement une invention.")
        else:
            constat = (f"Des sources indépendantes signalent {domaine} comme "
                       "dangereux. N'ouvrez pas ce site et ne saisissez aucune "
                       "information personnelle.")
        return {
            "titre": "Ce site présente un danger sérieux",
            "texte": constat,
            "conseil": ("Supprimez le message qui contenait ce lien. Si vous avez "
                        "déjà saisi un mot de passe, changez-le immédiatement "
                        "sur le site officiel concerné, et prévenez votre banque "
                        "si vous y avez donné des coordonnées bancaires."),
        }
    if niveau == "defavorable":
        if nombre > 1:
            titre = "Ce site présente plusieurs signes inquiétants"
            constat = f"Plusieurs éléments vont à l'encontre de {domaine}."
        else:
            titre = "Ce site présente un signe inquiétant"
            constat = f"Un élément sérieux va à l'encontre de {domaine}."
        return {
            "titre": titre,
            "texte": (f"{constat} Rien ne prouve formellement qu'il soit "
                      "malveillant, mais l'indice relevé justifie la méfiance."),
            "conseil": ("Évitez d'y saisir un mot de passe, un numéro de carte "
                        "bancaire ou des informations personnelles. Si vous devez "
                        "y accéder, passez par un lien que vous avez tapé "
                        "vous-même plutôt que par celui reçu."),
        }
    if niveau == "attention":
        return {
            "titre": "Ce site appelle à la prudence",
            "texte": (f"{domaine} présente un ou deux points qui méritent votre "
                      "attention, sans que l'ensemble soit alarmant."),
            "conseil": ("Vérifiez l'adresse affichée dans la barre du navigateur "
                        "avant de vous connecter. En cas de doute, rendez-vous "
                        "directement sur le site en tapant son adresse, plutôt "
                        "qu'en suivant un lien reçu par message ou par courriel."),
        }
    if niveau == "favorable":
        return {
            "titre": "Aucun signe défavorable détecté",
            "texte": (f"Les contrôles effectués sur {domaine} n'ont révélé aucun "
                      "élément préoccupant : le domaine existe depuis longtemps, "
                      "sa connexion est chiffrée et il n'est signalé nulle part."),
            "conseil": ("Cela ne garantit pas l'honnêteté de son propriétaire. "
                        "Restez vigilant si l'on vous demande de payer par un "
                        "moyen inhabituel, ou de communiquer des codes reçus par "
                        "message."),
        }
    return {
        "titre": "Vérification incomplète",
        "texte": (f"Les sources interrogées n'ont pas permis de vérifier "
                  f"{domaine} de façon suffisante. L'absence de signal défavorable "
                  "ne signifie pas que le site est sûr : elle signifie que nous "
                  "n'avons pas pu conclure."),
        "conseil": ("En l'absence de conclusion, appliquez les précautions "
                    "habituelles : ne saisissez rien de sensible, et vérifiez "
                    "l'adresse du site auprès d'une source officielle."),
    }


def _signes_favorables(donnees: Dict[str, Any]) -> List[str]:
    """Éléments rassurants, en français courant."""
    signes: List[str] = []
    rdap = donnees.get("rdap") or {}

    age = rdap.get("age_days")
    if isinstance(age, int):
        if age >= 3650:
            signes.append(f"Ce site existe depuis plus de {age // 365} ans.")
        elif age >= 365:
            annees = age // 365
            signes.append(f"Ce site existe depuis "
                          f"{annees} an{'s' if annees > 1 else ''}.")
        elif age < 90:
            pass                    # un site récent n'est pas un signe favorable
        else:
            signes.append("Ce site existe depuis plusieurs mois.")

    https = donnees.get("https") or {}
    if https.get("ok"):
        signes.append("La connexion à ce site est chiffrée : les informations "
                      "échangées ne peuvent pas être lues en route.")

    ssl = donnees.get("ssl_labs") or {}
    if ssl.get("disponible") and ssl.get("note") in ("A+", "A", "A-"):
        signes.append(f"Sa configuration de sécurité a reçu la note "
                      f"{ssl['note']} (sur une échelle de A à F), ce qui est "
                      "un bon résultat.")

    vt = donnees.get("virus_total") or {}
    if vt.get("disponible") and not vt.get("moteurs_malveillants") \
            and not vt.get("moteurs_suspects"):
        total = vt.get("moteurs_total")
        if total:
            signes.append(f"Aucun des {total} logiciels de sécurité consultés ne "
                          "signale ce site.")

    ip = donnees.get("ip") or {}
    operateur = (ip.get("operateur") or {}).get("categorie")
    if operateur == "hebergement" and ip.get("proprietaire"):
        signes.append(f"Le site est hébergé par {ip['proprietaire']}, un "
                      "hébergeur professionnel.")

    return signes


def _signes_defavorables(donnees: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Éléments préoccupants, en français courant, chacun avec sa gravité.

    La gravité est portée par le signe lui-même plutôt que déduite ensuite en
    cherchant des mots dans la phrase. La première version procédait par
    recherche de « dangereux » ou « malveillant » dans le texte produit : un
    domaine non enregistré, dont le message ne contenait aucun de ces mots,
    était alors classé simple « prudence » au lieu de danger avéré.

    Gravités :
      critique — l'usage légitime est exclu, ou un danger est confirmé ;
      eleve    — signal sérieux, à traiter comme tel ;
      moyen    — point de vigilance réel mais non concluant.
    """
    signes: List[Dict[str, str]] = []

    def ajouter(texte: str, gravite: str = "moyen") -> None:
        signes.append({"texte": texte, "gravite": gravite})

    rdap = donnees.get("rdap") or {}
    dns = donnees.get("dns") or {}

    # --- Danger avéré ---
    if donnees.get("registered") is False:
        ajouter("Ce domaine n'est enregistré par personne. Un message portant "
                "cette adresse ne peut venir que d'un expéditeur qui l'a "
                "inventée : il n'existe aucun site légitime à cette adresse.",
                "critique")

    vt = donnees.get("virus_total") or {}
    if vt.get("disponible") and (vt.get("moteurs_malveillants") or 0) > 0:
        ajouter(vt.get("phrase") or "Des logiciels de sécurité signalent ce site "
                                    "comme dangereux.", "critique")

    if dns.get("divergence"):
        ajouter(dns["divergence"], "eleve")

    # --- Signaux sérieux ---
    if vt.get("disponible") and (vt.get("moteurs_suspects") or 0) >= 2:
        ajouter(vt.get("phrase") or "Plusieurs logiciels de sécurité jugent ce "
                                    "site suspect.", "eleve")

    age = rdap.get("age_days")
    if isinstance(age, int):
        if age < 30:
            ajouter(f"Ce site n'existe que depuis {age} jours. Les sites créés "
                    "pour tromper sont presque toujours utilisés dans leurs "
                    "premiers jours.", "eleve")
        elif age < 90:
            ajouter("Ce site est très récent : il a été créé il y a "
                    f"{age} jours.", "moyen")
        elif age < 365:
            ajouter("Ce site a moins d'un an.", "moyen")

    ssl = donnees.get("ssl_labs") or {}
    note = ssl.get("note")
    if ssl.get("disponible") and note in ("C", "D", "E", "F", "T", "M"):
        texte = (f"Sa configuration de sécurité a reçu la note {note} "
                 f"({ssl.get('niveau', 'insuffisante')}).")
        if ssl.get("explication"):
            texte += f" {ssl['explication']}"
        ajouter(texte, "eleve" if note in ("D", "E", "F", "T", "M") else "moyen")

    https = donnees.get("https") or {}
    if https.get("error"):
        ajouter("La connexion sécurisée à ce site pose problème : le navigateur "
                "ne peut pas garantir que vous parlez bien au bon site.", "eleve")
    if https.get("redirects_to_other_host"):
        ajouter("Ce site redirige vers une autre adresse, ce qui est fréquent "
                "dans les tentatives de tromperie.", "moyen")

    # --- Points de vigilance ---
    tld = donnees.get("tld") or ""
    if tld in {"tk", "ml", "ga", "cf", "gq", "top", "click", "work", "link",
               "country", "loan", "download", "stream", "gdn", "bid", "trade"}:
        ajouter(f"L'extension « .{tld} » est gratuite ou très bon marché, et "
                "massivement utilisée par les sites frauduleux.", "moyen")

    ip = donnees.get("ip") or {}
    if ip.get("vpn_ou_proxy"):
        ajouter("L'adresse du serveur est masquée derrière un service "
                "anonymisant, ce qui empêche d'identifier son exploitant.", "moyen")

    ct = donnees.get("cert_transparency") or {}
    sensibles = [e for e in (ct.get("environnements_exposes") or [])
                 if e.get("type") in ("administration", "base de données",
                                      "sauvegardes", "réseau interne",
                                      "intégration continue")]
    if sensibles:
        exemples = ", ".join(e["nom"] for e in sensibles[:2])
        ajouter(f"Ce domaine expose des services qui n'étaient pas destinés au "
                f"public ({exemples}), ce qui traduit une gestion approximative.",
                "moyen")

    return signes


def _gravite_maximale(signes: List[Dict[str, str]]) -> Optional[str]:
    """Gravité la plus élevée parmi les signes défavorables."""
    ordre = {"moyen": 1, "eleve": 2, "critique": 3}
    if not signes:
        return None
    return max((s["gravite"] for s in signes), key=lambda g: ordre.get(g, 0))


def _limites(donnees: Dict[str, Any]) -> List[str]:
    """
    Ce qui n'a pas pu être vérifié.

    Cette section est essentielle : sans elle, un utilisateur lisant « aucun
    signal défavorable » alors que la moitié des sources a échoué serait
    faussement rassuré.
    """
    limites: List[str] = []

    if not (donnees.get("rdap") or {}).get("age_days"):
        limites.append("L'âge du domaine n'a pas pu être vérifié.")
    if not donnees.get("rdap_available", True):
        limites.append("Le registre des noms de domaine n'a pas répondu : "
                       "les informations d'enregistrement manquent.")

    vt = donnees.get("virus_total") or {}
    if not vt.get("disponible"):
        if "clé absente" in str(vt.get("erreur", "")):
            limites.append("La vérification par les logiciels de sécurité n'est "
                           "pas activée (clé VirusTotal absente).")
        else:
            limites.append("La vérification par les logiciels de sécurité n'a "
                           "pas pu être effectuée.")

    ssl = donnees.get("ssl_labs") or {}
    if not ssl.get("disponible"):
        limites.append("La qualité de la configuration de sécurité n'a pas pu "
                       "être notée.")

    ct = donnees.get("cert_transparency") or {}
    if not ct.get("disponible"):
        limites.append("La recherche de sous-domaines n'a pas abouti.")

    # Une source que l'utilisateur doit connaître : le domaine peut être
    # parfaitement configuré et malhonnête.
    limites.append("Un site peut être techniquement irréprochable et servir à "
                   "escroquer : cette analyse porte sur la technique, pas sur "
                   "l'honnêteté de son propriétaire.")
    return limites


def resume(donnees: Dict[str, Any]) -> Dict[str, Any]:
    """
    Produit la synthèse en langage courant d'une fiche d'analyse.

    Reçoit l'enregistrement produit par analyzer.py, complété du niveau de
    risque technique, et retourne un dictionnaire prêt à afficher : conclusion,
    conseil, signes favorables, signes défavorables, limites.

    ÉCHELLE DE CONCLUSION

    La conclusion ne se déduit pas du seul score interne. Un score de 30
    composé de trois broutilles n'a pas la même signification qu'un unique
    signalement d'antivirus, pourtant compté pareil. Ce sont donc les signes
    concrets qui décident :

      un signalement de sécurité      -> critique
      trois signes défavorables ou plus -> défavorable
      un ou deux signes défavorables  -> attention
      aucun défavorable, des favorables -> favorable
      ni l'un ni l'autre              -> indéterminé
    """
    domaine = donnees.get("domain") or "ce site"
    niveau_technique = donnees.get("risk_level")

    favorables = _signes_favorables(donnees)
    defavorables = _signes_defavorables(donnees)
    gravite = _gravite_maximale(defavorables)

    if gravite == "critique":
        niveau = "critique"
    elif gravite == "eleve":
        niveau = "defavorable"
    elif gravite == "moyen":
        niveau = "attention"
    elif favorables:
        # Des éléments concrets ont pu être vérifiés, et aucun ne déplaît.
        # Le niveau technique sert de garde-fou : un score élevé sans signe
        # listé reste un motif de prudence.
        niveau = "favorable" if niveau_technique in (None, "LOW") else "attention"
    else:
        niveau = "indetermine"

    verdict = _verdict(niveau, domaine, defavorables)

    return {
        "niveau": niveau,
        "couleur": COULEURS[niveau],
        "titre": verdict["titre"],
        "texte": verdict["texte"],
        "conseil": verdict["conseil"],
        "signes_favorables": favorables,
        "signes_defavorables": defavorables,
        "gravite_defavorable": gravite,
        "limites": _limites(donnees),
    }


def phrase_courte(donnees: Dict[str, Any]) -> str:
    """Phrase unique, pour un affichage compact (historique, partage)."""
    r = resume(donnees)
    return f"{r['titre']} — {r['texte'].split('.')[0]}."
