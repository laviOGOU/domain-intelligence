"""
test_sources.py — Vérifications des sources externes et de la synthèse.

DEUX CATÉGORIES DE TESTS, VOLONTAIREMENT SÉPARÉES

  * Tests hors ligne — ils ne sortent pas sur Internet et vérifient la logique
    de décision : quelle conclusion pour quels signaux, quelle gravité, quel
    texte. Ce sont eux qui protègent contre les régressions, car ils ne
    dépendent ni du réseau ni de la disponibilité d'un service tiers.

  * Tests en ligne — ils interrogent réellement les sources. Ils sont
    indispensables pour détecter qu'un fournisseur a changé son format, mais
    ils peuvent échouer sans qu'il y ait de bug : un service gratuit peut être
    momentanément indisponible. Ils sont donc signalés comme tels.

Exécution :
    ./.venv/Scripts/python.exe test_sources.py            # tout
    ./.venv/Scripts/python.exe test_sources.py --hors-ligne  # sans réseau
"""
import sys
import traceback

# ---------------------------------------------------------------------------
# Jeu de données de référence, imitant la sortie d'analyzer.py.
# ---------------------------------------------------------------------------
def _donnees(**remplacements):
    """Fiche d'analyse type, que chaque test modifie selon son besoin."""
    base = {
        "domain": "exemple.com",
        "tld": "com",
        "registered": True,
        "rdap_available": True,
        "rdap": {"age_days": 4000, "registrar": "Exemple Registrar"},
        "dns": {"ns": ["a.gtld-servers.net"], "mx": [], "txt": []},
        "ip": {"ip": "203.0.113.10", "proprietaire": "Exemple Hosting SAS",
               "organisation": "Exemple Hosting SAS",
               "pays": "FR", "asn": "AS1234"},
        "https": {"ok": True, "status_code": 200,
                  "redirects_to_other_host": False, "error": None},
        "ssl_labs": {"disponible": True, "note": "A", "niveau": "excellent"},
        "virus_total": {"disponible": True, "moteurs_malveillants": 0,
                        "moteurs_suspects": 0, "moteurs_total": 72},
        "cert_transparency": {"disponible": True, "nombre": 3,
                              "environnements_exposes": []},
        "urlscan": {"available": True},
        "risk_level": "LOW",
    }
    base.update(remplacements)
    return base


# ---------------------------------------------------------------------------
# Cadre de test minimal
# ---------------------------------------------------------------------------
_resultats = {"ok": 0, "ko": 0, "ignores": 0}
_anomalies = []


def verifier(condition, description):
    if condition:
        _resultats["ok"] += 1
        print(f"  OK    {description}")
    else:
        _resultats["ko"] += 1
        _anomalies.append(description)
        print(f"  ECHEC {description}")


def egal(obtenu, attendu, description):
    if obtenu == attendu:
        _resultats["ok"] += 1
        print(f"  OK    {description}")
    else:
        _resultats["ko"] += 1
        _anomalies.append(f"{description} — attendu {attendu!r}, obtenu {obtenu!r}")
        print(f"  ECHEC {description}")
        print(f"          attendu : {attendu!r}")
        print(f"          obtenu  : {obtenu!r}")


def ignorer(raison):
    _resultats["ignores"] += 1
    print(f"  IGNORE {raison}")


# ---------------------------------------------------------------------------
# 1. Synthèse en langage courant — tests hors ligne
# ---------------------------------------------------------------------------
def test_synthese():
    print("\n1. SYNTHESE EN LANGAGE COURANT (hors ligne)")
    import explications

    # Un domaine sain doit être annoncé comme tel. Ce test protège contre une
    # régression déjà survenue : la fonction ne recevait pas le niveau
    # technique et concluait « vérification incomplète » sur github.com.
    r = explications.resume(_donnees())
    egal(r["niveau"], "favorable", "domaine sain -> conclusion favorable")
    verifier(r["signes_favorables"], "domaine sain -> au moins un signe favorable")
    verifier(not r["signes_defavorables"], "domaine sain -> aucun signe défavorable")

    # Domaine non enregistré : danger, pas simple prudence.
    r = explications.resume(_donnees(
        registered=False, rdap={"age_days": None},
        https={"ok": False, "error": "Connexion impossible"},
    ))
    egal(r["niveau"], "critique", "domaine non enregistré -> critique")
    verifier("invention" in r["texte"] or "aucun site" in r["texte"].lower(),
             "domaine non enregistré -> phrase exacte, sans 'sources signalent'")
    verifier("signalent" not in r["texte"],
             "domaine non enregistré -> ne prétend pas que des sources le signalent")

    # Site signalé par les antivirus : danger confirmé.
    r = explications.resume(_donnees(**{
        "virus_total": {"disponible": True, "moteurs_malveillants": 7,
                        "moteurs_suspects": 0, "moteurs_total": 72,
                        "phrase": "7 moteurs sur 72 signalent ce site comme dangereux."},
    }))
    egal(r["niveau"], "critique", "site signalé par les antivirus -> critique")
    verifier(any("7 moteurs" in s["texte"] for s in r["signes_defavorables"]),
             "site signalé -> le nombre de moteurs apparaît")

    # Domaine très récent : signal sérieux, mais pas un constat de danger.
    r = explications.resume(_donnees(rdap={"age_days": 12}))
    egal(r["niveau"], "defavorable", "domaine de 12 jours -> défavorable")

    # Domaine de moins d'un an : point de vigilance seulement.
    r = explications.resume(_donnees(rdap={"age_days": 200}))
    egal(r["niveau"], "attention", "domaine de 200 jours -> attention")

    # Une source indisponible ne doit jamais être présentée comme un danger.
    r = explications.resume(_donnees(**{
        "virus_total": {"disponible": False, "erreur": "clé absente"},
        "ssl_labs": {"disponible": False, "erreur": "délai dépassé"},
        "cert_transparency": {"disponible": False, "erreur": "502"},
    }))
    egal(r["niveau"], "favorable",
         "sources indisponibles -> pas de pénalité, conclusion inchangée")
    verifier(any("VirusTotal" in l for l in r["limites"]),
             "source indisponible -> mentionnée dans les limites")
    verifier(any("configuration de sécurité" in l for l in r["limites"]),
             "SSL Labs indisponible -> mentionné dans les limites")
    # Note pour la relecture : ne pas chercher « note » ici. Le message dit
    # « n'a pas pu être notée », et « notée » s'écrit n-o-t-é-e : la séquence
    # « note » n'y figure pas. Le piège a coûté un test faussement rouge.

    # Les limites doivent toujours rappeler que la technique ne dit pas
    # l'honnêteté.
    r = explications.resume(_donnees())
    verifier(any("honnêteté" in l for l in r["limites"]),
             "les limites rappellent que la technique ne juge pas l'honnêteté")

    # Le texte reste du français courant : aucun jargon ne doit y apparaître.
    jargon = ["RDAP", "TLS", "DNS", "API", "ASN", "HTTP", "registrar", "SSL"]
    for cas, donnees in [
        ("sain", _donnees()),
        ("non enregistré", _donnees(registered=False, rdap={"age_days": None})),
        ("récent", _donnees(rdap={"age_days": 15})),
        ("signalé", _donnees(virus_total={"disponible": True,
                                          "moteurs_malveillants": 3,
                                          "moteurs_suspects": 0,
                                          "moteurs_total": 70})),
    ]:
        r = explications.resume(donnees)
        trouves = [m for m in jargon if m in r["texte"] or m in r["conseil"]]
        verifier(not trouves,
                 f"conclusion « {cas} » sans jargon (trouvé : {trouves or 'aucun'})")


# ---------------------------------------------------------------------------
# 2. Moteur de score — tests hors ligne
# ---------------------------------------------------------------------------
def test_score():
    print("\n2. MOTEUR DE SCORE (hors ligne)")
    import risk

    # IMPORTANT — le score est borné à 0. Sur un domaine parfaitement sain, le
    # total vaut déjà 0 : un bonus de -6 n'y change rien et toute comparaison
    # serait vide de sens. Les tests de comparaison partent donc d'un domaine
    # imparfait, dont le score laisse de la marge dans les deux sens.
    def avec_marge(**remplacements):
        return _donnees(**{
            "rdap": {"age_days": 200, "registrar": "Exemple Registrar"},
            **remplacements,
        })

    sans = risk.evaluate(avec_marge(ssl_labs={"disponible": False}))
    avec = risk.evaluate(avec_marge(ssl_labs={"disponible": True, "note": "A+"}))
    verifier(avec["risk_score"] < sans["risk_score"],
             f"note TLS A+ -> score allégé ({sans['risk_score']} -> {avec['risk_score']})")

    # Une note TLS dégradée doit l'alourdir nettement.
    mauvais = risk.evaluate(avec_marge(
        ssl_labs={"disponible": True, "note": "F", "niveau": "défaillant"}))
    verifier(mauvais["risk_score"] >= sans["risk_score"] + 15,
             f"note TLS F -> score alourdi d'au moins 15 points "
             f"({sans['risk_score']} -> {mauvais['risk_score']})")

    # Un signalement d'antivirus doit dominer le calcul, y compris quand le
    # domaine est ancien, bien chiffré et bien hébergé. Sans plancher, ces
    # bonnes notes compensaient le signalement et le niveau retombait à
    # « modéré » — précisément ce qu'obtiendrait un escroc soigneux.
    signale = risk.evaluate(_donnees(**{          # domaine par ailleurs parfait
        "virus_total": {"disponible": True, "moteurs_malveillants": 5,
                        "moteurs_suspects": 0, "moteurs_total": 70}}))
    egal(signale["risk_level"], "HIGH",
         "5 moteurs signalent -> niveau élevé malgré tous les points favorables")
    verifier(signale["risk_score"] >= 55,
             "signalement confirmé -> score au moins égal au seuil élevé")
    verifier(any(f["label"] == "Site malveillant confirmé"
                 for f in signale["risk_factors"]),
             "le signalement figure explicitement parmi les facteurs")

    # Une source indisponible ne doit rien apporter : ni pénalité, ni bonus.
    # Elle doit se comporter exactement comme une source jamais interrogée.
    #
    # Nuance à ne pas perdre de vue : une source qui a répondu « rien à
    # signaler » apporte un vrai bonus (-10 chez VirusTotal). Son absence
    # supprime ce bonus, ce qui relève le score — et c'est normal, car on ne
    # sait alors rien. Comparer les deux cas produirait un faux échec.
    jamais_interroge = risk.evaluate(avec_marge(
        ssl_labs=None, virus_total=None))
    indisponible = risk.evaluate(avec_marge(**{
        "virus_total": {"disponible": False, "erreur": "panne"},
        "ssl_labs": {"disponible": False, "erreur": "panne"}}))
    egal(indisponible["risk_score"], jamais_interroge["risk_score"],
         "source indisponible -> même score qu'une source jamais interrogée")

    # Et une panne ne doit jamais pénaliser davantage que le problème réel.
    en_panne = risk.evaluate(avec_marge(**{
        "virus_total": {"disponible": False, "erreur": "panne"},
        "ssl_labs": {"disponible": False, "erreur": "panne"}}))
    en_probleme = risk.evaluate(avec_marge(
        ssl_labs={"disponible": True, "note": "F"}))
    verifier(en_panne["risk_score"] < en_probleme["risk_score"],
             "une source en panne pénalise moins qu'un vrai problème")

    # L'écart d'adresses entre résolveurs ne doit PAS pénaliser : c'est le
    # fonctionnement normal de tout site réparti sur plusieurs serveurs.
    ecart = risk.evaluate(avec_marge(**{
        "dns": {"ns": [], "mx": [], "adresses_divergent": True, "divergence": None}}))
    normal = risk.evaluate(avec_marge(**{
        "dns": {"ns": [], "mx": [], "adresses_divergent": False, "divergence": None}}))
    egal(ecart["risk_score"], normal["risk_score"],
         "adresses différentes selon le résolveur -> aucune pénalité")

    # Un désaccord sur l'EXISTENCE, lui, doit être relevé.
    contradiction = risk.evaluate(avec_marge(**{
        "dns": {"ns": [], "divergence": "Un résolveur annonce le domaine, "
                                        "l'autre déclare qu'il n'existe pas."}}))
    verifier(contradiction["risk_score"] > normal["risk_score"],
             f"désaccord sur l'existence du nom -> signal relevé "
             f"({normal['risk_score']} -> {contradiction['risk_score']})")


# ---------------------------------------------------------------------------
# 3. Sources en ligne
# ---------------------------------------------------------------------------
def test_dns():
    print("\n3. RESOLUTION DNS PAR RESOLVEURS PUBLICS (en ligne)")
    from providers import dns_doh

    r = dns_doh.resoudre("github.com")
    verifier(r.get("existe") is True, "github.com existe")
    verifier(r.get("ipv4"), "github.com -> au moins une adresse IPv4")
    adresses = r.get("ipv4") or []
    verifier(all(a.count(".") == 3 for a in adresses),
             "adresses IPv4 bien formées")
    verifier("Cloudflare" in (r.get("source") or ""),
             "la source indique les résolveurs employés")

    # Le jeu de tests RFC 2606 ne doit pas exister.
    r = dns_doh.resoudre("domaine-inexistant-sans-doute-xyz123.com")
    verifier(r.get("existe") is False,
             "domaine inexistant -> correctement déclaré inexistant")

    rec = dns_doh.enregistrements("github.com")
    verifier(rec.get("ns"), "github.com -> serveurs de noms listés")
    verifier(rec.get("mx"), "github.com -> serveurs de messagerie listés")
    verifier(not rec.get("erreur"), "aucune erreur signalée")


def test_ip():
    print("\n4. PROPRIETAIRE ET LOCALISATION D'ADRESSE (en ligne)")
    from providers import ip_info

    r = ip_info.localiser("8.8.8.8")
    verifier(r.get("proprietaire"), "8.8.8.8 -> propriétaire identifié")
    verifier(r.get("pays"), "8.8.8.8 -> pays identifié")
    verifier("Google" in str(r.get("organisation") or r.get("proprietaire")),
             "8.8.8.8 -> exploitant reconnu comme Google")

    # Cas particulier : 1.1.1.1 est allouée au registre APNIC, qui la délègue à
    # Cloudflare. Le titulaire enregistré n'est donc pas l'exploitant, et
    # afficher « APNIC » serait exact mais trompeur.
    r = ip_info.localiser("1.1.1.1")
    verifier("Cloudflare" in str(r.get("organisation") or ""),
             "1.1.1.1 -> exploitant affiché (Cloudflare), pas le registre")
    verifier(str(r.get("operateur", {}).get("categorie")) == "hebergement",
             "1.1.1.1 -> classé hébergeur professionnel")

    r = ip_info.localiser("192.0.2.1")
    verifier(r.get("ip") == "192.0.2.1",
             "adresse de documentation -> traitée sans plantage")


def test_ssl_labs():
    print("\n5. NOTE DU CHIFFREMENT (en ligne)")
    from providers import ssl_labs

    # Signature réelle : evaluer(domaine). Le premier jet de ce test passait un
    # paramètre « attente_max » qui n'existe pas — l'API avait été imaginée au
    # lieu d'être lue. Le délai d'attente se règle dans config.py
    # (SSLLABS_MAX_WAIT), et non par un argument.
    r = ssl_labs.evaluer("github.com")
    if not r.get("disponible"):
        ignorer(f"service indisponible pour l'instant : {r.get('erreur')}")
        return

    notes_valides = ("A+", "A", "A-", "B", "C", "D", "E", "F", "T", "M")
    verifier(r.get("note") in notes_valides,
             f"note valide obtenue ({r.get('note')})")
    verifier(r.get("niveau"), "la note est accompagnée d'une appréciation")
    verifier(isinstance(r.get("explication"), str) and r.get("explication"),
             "une explication en français accompagne la note")
    verifier(isinstance(r.get("protocoles"), list),
             f"les versions du protocole sont listées ({r.get('protocoles')})")
    verifier(isinstance(r.get("avertissements"), bool),
             "la présence d'avertissements est signalée")
    verifier(r.get("serveur"), "le serveur interrogé est identifié")


def test_crtsh():
    print("\n6. SOUS-DOMAINES PAR LES JOURNAUX DE CERTIFICATS (en ligne)")
    from providers import cert_transparency

    r = cert_transparency.sous_domaines("github.com")
    if not r.get("disponible"):
        ignorer(f"service gratuit surchargé : {r.get('erreur')} — "
                "comportement attendu, l'échec est signalé et non masqué")
        return
    verifier(r.get("nombre") and r["nombre"] > 0,
             f"sous-domaines trouvés ({r.get('nombre')})")
    noms = r.get("sous_domaines") or []
    verifier(all("github.com" in n for n in noms),
             "tous les noms appartiennent bien au domaine étudié")
    verifier(isinstance(r.get("environnements_exposes"), list),
             "les environnements exposés sont classés")


def test_virustotal():
    print("\n7. REPUTATION PAR VIRUSTOTAL (configuration)")
    from providers import virus_total

    r = virus_total.reputation("github.com")
    if not r.get("disponible"):
        # Sans clé, la source doit s'effacer proprement, sans erreur levée et
        # sans résultat inventé.
        verifier("clé absente" in str(r.get("erreur")) or r.get("erreur"),
                 "sans clé -> absence signalée proprement, aucune exception")
        verifier("moteurs_total" not in r or r.get("moteurs_total") is None,
                 "sans clé -> aucun verdict inventé")
        ignorer("clé VirusTotal non configurée")
        return
    verifier(r.get("moteurs_total"), "nombre de moteurs consultés renseigné")
    verifier(r.get("phrase"), "phrase de synthèse produite")


def test_analyse_complete():
    print("\n8. ANALYSE COMPLETE DE BOUT EN BOUT (en ligne)")
    import analyzer

    r = analyzer.analyze("github.com")
    verifier(r.get("domain") == "github.com", "domaine correctement normalisé")
    verifier(r.get("registered") is True, "domaine reconnu comme enregistré")
    verifier(isinstance(r.get("domain_age_days"), int),
             "âge du domaine calculé")
    verifier(r.get("ip"), "adresse IP résolue")
    verifier(r.get("https_ok") is True, "HTTPS valide")
    verifier("synthese" in r, "synthèse en langage courant présente")
    egal(r["synthese"]["niveau"], "favorable",
         "github.com -> conclusion favorable")
    verifier(not r.get("errors"), f"aucune erreur technique ({r.get('errors')})")


def main():
    hors_ligne = "--hors-ligne" in sys.argv
    print("=" * 72)
    print("  DOMAIN INTELLIGENCE — verification des sources externes")
    print("=" * 72)

    test_synthese()
    test_score()

    if hors_ligne:
        print("\n  (tests en ligne ignorés sur demande)")
    else:
        for fonction in (test_dns, test_ip, test_ssl_labs, test_crtsh,
                         test_virustotal, test_analyse_complete):
            try:
                fonction()
            except Exception:                                  # noqa: BLE001
                _resultats["ko"] += 1
                _anomalies.append(f"{fonction.__name__} a levé une exception")
                print(f"  ECHEC {fonction.__name__} a levé une exception :")
                traceback.print_exc()

    total = _resultats["ok"] + _resultats["ko"]
    print("\n" + "=" * 72)
    print(f"  {_resultats['ok']}/{total} vérification(s) réussie(s)"
          f"   ({_resultats['ignores']} ignorée(s) faute de service disponible)")
    if _anomalies:
        print("\n  Anomalies :")
        for a in _anomalies:
            print(f"    - {a}")
    print("=" * 72)
    return 1 if _resultats["ko"] else 0


if __name__ == "__main__":
    sys.exit(main())
