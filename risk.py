"""
risk.py — Attribution d'un niveau de risque à partir des données collectées.

Principe : chaque signal détecté ajoute des points, chaque signal rassurant en
retire. Le total est borné à [0, 100]. Les règles sont volontairement lisibles et
sont affichées dans l'interface : l'analyste voit *pourquoi* un domaine est jugé
risqué, il ne subit pas une note opaque.

Seuils (modifiables dans .env) :
    score < 25        -> LOW
    25 <= score < 55  -> MEDIUM
    score >= 55       -> HIGH
"""
from typing import Any, Dict, List

from config import RISK_HIGH_THRESHOLD, RISK_MEDIUM_THRESHOLD

# TLD régulièrement associés à l'abus (gratuits ou très bon marché).
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",            # Freenom
    "top", "click", "work", "link", "rest", "country", "kim", "loan", "download",
    "zip", "mov", "review", "stream", "gdn", "bid", "trade", "date", "party",
}

# Mots employés dans les campagnes d'hameçonnage.
PHISHING_KEYWORDS = {
    "login", "signin", "secure", "security", "verify", "verification", "account",
    "update", "confirm", "bank", "banking", "wallet", "crypto", "payment",
    "invoice", "support", "helpdesk", "recovery", "password", "auth",
}

TLD_COUNTRY_HINTS = {
    "fr": "France", "be": "Belgique", "ch": "Suisse", "ca": "Canada", "de": "Allemagne",
    "uk": "Royaume-Uni", "us": "États-Unis", "ci": "Côte d'Ivoire", "sn": "Sénégal",
    "bj": "Bénin", "tg": "Togo", "bf": "Burkina Faso", "ml": "Mali", "cm": "Cameroun",
}


def _add(factors: List[Dict[str, Any]], label: str, points: int, detail: str) -> None:
    factors.append({"label": label, "points": points, "detail": detail})


def evaluate(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calcule le score et le niveau de risque.

    `data` attend les clés produites par analyzer.py :
      domain, tld, rdap, ip, https, dns, registered, rdap_available

    Règle importante : une donnée *manquante à cause d'une panne de notre côté*
    (registre RDAP injoignable) ne compte pas comme un risque. Elle est signalée
    comme limite d'analyse, pas comme pénalité. Sans quoi le score dependrait de
    la disponibilité du réseau au moment du test.
    """
    factors: List[Dict[str, Any]] = []
    rdap = data.get("rdap") or {}
    ip = data.get("ip") or {}
    https = data.get("https") or {}
    domain = data.get("domain", "")
    tld = data.get("tld", "")
    registered = data.get("registered", True)
    rdap_available = data.get("rdap_available", True)

    label = domain.split(".")[0] if domain else ""

    # ------------------------------------------------------------------
    # Cas 1 : le domaine n'existe pas dans le registre.
    # Les vérifications techniques (DNS, HTTPS) échouent forcément : les compter
    # reviendrait à pénaliser deux fois le même fait.
    # ------------------------------------------------------------------
    if not registered:
        _add(factors, "Domaine non enregistré", 40,
             "Aucun enregistrement au registre : le nom n'est pas attribué. "
             "Un message provenant de ce domaine serait donc forgé.")
        _check_tld(factors, tld)
        _check_name_pattern(factors, label)
        return _finalise(factors)

    # ------------------------------------------------------------------
    # Cas 2 : domaine enregistré (analyse complète)
    # ------------------------------------------------------------------
    if rdap_available:
        # 1. Âge du domaine — le signal le plus discriminant
        age = rdap.get("age_days")
        if age is None:
            _add(factors, "Âge non publié", 5,
                 "Le registre ne publie pas la date de création.")
        elif age < 30:
            _add(factors, "Domaine très récent", 40,
                 f"Créé il y a {age} jours : les domaines d'hameçonnage sont souvent "
                 "utilisés dans leurs premiers jours.")
        elif age < 90:
            _add(factors, "Domaine récent", 30, f"Créé il y a {age} jours (moins de 3 mois).")
        elif age < 365:
            _add(factors, "Domaine jeune", 18, f"Créé il y a {age} jours (moins d'un an).")
        elif age < 1095:
            _add(factors, "Domaine établi", 8, f"Créé il y a {age} jours (1 à 3 ans).")
        else:
            _add(factors, "Domaine ancien", 0,
                 f"Créé il y a {age} jours ({age // 365} ans) — ancienneté rassurante.")

        # 2. Expiration
        days_left = rdap.get("days_until_expiry")
        if days_left is not None and days_left < 0:
            _add(factors, "Domaine expiré", 20, f"Expiré depuis {abs(days_left)} jours.")
        elif days_left is not None and days_left < 60:
            _add(factors, "Expiration imminente", 12,
                 f"Expire dans {days_left} jours (renouvellement non effectué).")

        # 3. Registrar
        if not rdap.get("registrar"):
            _add(factors, "Registrar non publié", 8,
                 "Le registre ne fournit pas le nom du bureau d'enregistrement.")
    else:
        _add(factors, "Registre RDAP injoignable", 0,
             "Les données d'enregistrement (âge, expiration, registrar) n'ont pas pu "
             "être vérifiées : panne ou quota dépassé côté registre. Le score porte "
             "uniquement sur les contrôles techniques.")

    # 4. Chiffrement
    if https.get("ok"):
        _add(factors, "HTTPS valide", 0, f"Certificat accepté (HTTP {https.get('status_code')}).")
    elif https.get("error"):
        _add(factors, "HTTPS indisponible ou invalide", 25, str(https["error"]))
    else:
        _add(factors, "Site web injoignable", 15, "Le domaine ne répond pas en HTTPS.")

    # 5. Extension
    _check_tld(factors, tld)

    # 6. Résolution DNS
    if not ip.get("ip"):
        _add(factors, "Aucune adresse IP", 20,
             "Le domaine ne résout pas : site inexistant ou infrastructure retirée.")

    # 7. Nom de domaine
    _check_name_pattern(factors, label)

    # 8. Redirection vers un autre hôte
    if https.get("redirects_to_other_host"):
        _add(factors, "Redirection vers un autre domaine", 10,
             f"Redirige vers {https.get('final_url')}.")

    # 9. Proxy / VPN
    if ip.get("vpn_ou_proxy"):
        _add(factors, "Proxy ou VPN détecté", 10,
             "L'adresse IP est signalée comme masquée, ce qui empêche "
             "d'identifier l'hébergeur réel.")

    # --- Note de configuration TLS (Qualys SSL Labs) ---
    # Une note faible est un vrai signal : elle traduit un serveur mal tenu, et
    # un serveur mal tenu est plus souvent compromis. Une source indisponible
    # n'est PAS pénalisée : une panne de notre côté ne doit pas dégrader la
    # réputation d'un domaine.
    ssl_data = data.get("ssl_labs") or {}
    if ssl_data.get("disponible"):
        note = ssl_data.get("note")
        if note in ("A+", "A", "A-"):
            _add(factors, f"Configuration TLS notée {note}", -6,
                 f"Qualys SSL Labs attribue la note {note} à ce serveur.")
        elif note in ("B", "C"):
            _add(factors, f"Configuration TLS notée {note}", 6,
                 str(ssl_data.get("explication") or
                     "Configuration perfectible, souvent par maintien "
                     "d'anciennes versions du protocole."))
        elif note in ("D", "E", "F"):
            _add(factors, f"Configuration TLS notée {note}", 20,
                 str(ssl_data.get("explication") or
                     "Le chiffrement du site est mal configuré."))
        elif note in ("T", "M"):
            _add(factors, f"Configuration TLS notée {note}", 25,
                 str(ssl_data.get("explication") or
                     "Le certificat du site ne correspond pas au domaine."))

    # --- Réputation (VirusTotal) ---
    # La source la plus lourde du calcul : un seul moteur qui signale est plus
    # parlant que dix imprécisions de configuration.
    vt_data = data.get("virus_total") or {}
    if vt_data.get("disponible"):
        malveillants = vt_data.get("moteurs_malveillants") or 0
        suspects = vt_data.get("moteurs_suspects") or 0
        total = vt_data.get("moteurs_total") or 0
        if malveillants:
            _add(factors, "Site malveillant confirmé", 55,
                 f"{malveillants} moteur(s) de sécurité sur {total} signalent "
                 f"ce domaine comme dangereux.")
        elif suspects >= 2:
            _add(factors, "Site jugé suspect", 25,
                 f"{suspects} moteurs sur {total} le jugent suspect.")
        elif suspects == 1:
            _add(factors, "Un moteur émet un doute", 10,
                 f"1 moteur sur {total} le juge suspect.")
        elif total:
            _add(factors, "Aucun signalement de sécurité", -10,
                 f"Aucun des {total} moteurs consultés ne signale ce domaine.")

    # --- Cohérence entre résolveurs DNS ---
    # Ne vise que le désaccord sur l'EXISTENCE du nom, pas l'écart d'adresses :
    # deux résolveurs renvoient normalement des adresses différentes pour tout
    # site réparti sur plusieurs serveurs (Google, GitHub). Pénaliser cet écart
    # reviendrait à suspecter les sites les plus légitimes.
    dns_data = data.get("dns") or {}
    if dns_data.get("divergence"):
        _add(factors, "Réponses DNS contradictoires", 12,
             str(dns_data["divergence"]))

    # 10. Réputation observée via urlscan.io (API externe)
    urlscan = data.get("urlscan") or {}
    if urlscan.get("available"):
        rank = urlscan.get("popularity_rank")
        total = urlscan.get("total_scans") or 0
        age = rdap.get("age_days")
        if isinstance(rank, int) and rank <= 100_000:
            _add(factors, "Domaine parmi les plus visités", -8,
                 f"Classé n° {rank} des domaines les plus consultés du web "
                 "(Cisco Umbrella, relevé par urlscan.io).")
        elif total == 0 and isinstance(age, int) and age < 365:
            _add(factors, "Jeune domaine jamais observé", 12,
                 "Aucun scan public de ce domaine sur urlscan.io alors qu'il a moins "
                 f"d'un an ({age} jours) : il n'a encore attiré l'attention d'aucun "
                 "analyste, ce qui est fréquent pour les domaines frauduleux très récents.")

    # Bonus : ancienneté + chiffrement correct
    age = rdap.get("age_days")
    if age is not None and age >= 3650 and https.get("ok"):
        _add(factors, "Bonus : domaine ancien et sécurisé", -10,
             f"Plus de 10 ans d'existence ({age // 365} ans) et HTTPS valide.")

    return _finalise(factors)


def _check_tld(factors: List[Dict[str, Any]], tld: str) -> None:
    if tld in SUSPICIOUS_TLDS:
        _add(factors, "Extension à risque", 15,
             f"L'extension .{tld} est fréquemment utilisée pour des campagnes malveillantes.")
    else:
        _add(factors, "Extension courante", 0,
             f".{tld} ne figure pas dans la liste des extensions à risque.")


def _check_name_pattern(factors: List[Dict[str, Any]], label: str) -> None:
    matched = sorted({kw for kw in PHISHING_KEYWORDS if kw in label})
    if matched:
        _add(factors, "Termes sensibles dans le nom", 10,
             "Contient " + ", ".join(f"« {kw} »" for kw in matched) +
             " : vocabulaire typique des tentatives d'hameçonnage.")
    digits = sum(1 for c in label if c.isdigit())
    if digits >= 4:
        _add(factors, "Nom à forte densité de chiffres", 8,
             f"{digits} chiffres dans « {label} » : schéma courant pour les domaines générés.")
    if label.count("-") >= 3:
        _add(factors, "Nom très découpé", 6,
             f"{label.count('-')} tirets : typique des domaines générés automatiquement.")


def _finalise(factors: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Agrège les facteurs, borne le score et en déduit le niveau.

    PLANCHER DE SÉCURITÉ

    Un signalement d'antivirus ne se compense pas par une bonne hygiène. Un
    domaine signalé par cinq moteurs obtenait « risque modéré » dès lors qu'il
    était ancien, correctement chiffré et hébergé chez un professionnel : ces
    bonnes notes, cumulées, effaçaient le signalement. C'est exactement le
    calcul qu'un escroc soigneux obtient.

    D'où ce plancher : un signalement confirmé impose le niveau élevé, quels
    que soient les points favorables par ailleurs. Les facteurs restent tous
    affichés, pour que le lecteur voie sur quoi porte la réserve.
    """
    score = max(0, min(100, sum(f["points"] for f in factors)))

    signalement_confirme = any(f["label"] == "Site malveillant confirmé"
                               for f in factors)

    if score >= RISK_HIGH_THRESHOLD or signalement_confirme:
        level = "HIGH"
    elif score >= RISK_MEDIUM_THRESHOLD:
        level = "MEDIUM"
    else:
        level = "LOW"

    if signalement_confirme and score < RISK_HIGH_THRESHOLD:
        # Le score affiché doit rester cohérent avec le niveau annoncé : le
        # lecteur qui voit « 31 / 100 » et « risque élevé » sans explication
        # conclurait à une erreur de l'outil.
        score = RISK_HIGH_THRESHOLD

    return {
        "risk_score": score,
        "risk_level": level,
        "risk_factors": factors,
        "risk_thresholds": {"medium": RISK_MEDIUM_THRESHOLD, "high": RISK_HIGH_THRESHOLD},
        "risk_summary": summarise(level, factors),
    }


def summarise(level: str, factors: List[Dict[str, Any]]) -> str:
    """Phrase de synthèse pour la fiche : les 2 signaux les plus lourds."""
    heaviest = sorted([f for f in factors if f["points"] > 0],
                      key=lambda f: f["points"], reverse=True)[:2]
    if not heaviest:
        return "Aucun signal défavorable détecté : les indicateurs vérifiés sont cohérents."
    reasons = " ; ".join(f["label"].lower() for f in heaviest)
    prefix = {
        "HIGH": "Risque élevé",
        "MEDIUM": "Risque modéré",
        "LOW": "Risque faible",
    }[level]
    return f"{prefix} — principaux signaux : {reasons}."
