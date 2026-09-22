# Domain Intelligence — Sources réelles et résultats compréhensibles

**Projet :** Domain Intelligence
**Dossier :** `D:\PYTHON\Domain intelligent`
**Date :** 22 septembre 2026

---

## 1. Ce qui vous a été demandé

Deux remarques ont été faites sur la version précédente :

1. **« Il n'y a pas d'API réelle mais des services, ce qui fait que les résultats des analyses ne sont pas précis. »**
   Il fallait utiliser de vraies API, prises chez des prestataires reconnus mondialement.

2. **« Les résultats doivent être simples à comprendre pour des utilisateurs qui ne s'y connaissent pas en informatique. »**
   Il fallait que la fiche soit lisible par quelqu'un dont ce n'est pas le métier.

---

## 2. Diagnostic : ce qui était juste, et ce qui ne l'était pas

Avant de modifier quoi que ce soit, j'ai lu les quatre fournisseurs existants. Le constat est plus nuancé que la remarque ne le laissait penser.

**Deux fournisseurs étaient déjà de vraies API reconnues :**

- **RDAP** — c'est le protocole officiel de l'ICANN, par lequel les registres publient eux-mêmes les données d'enregistrement des noms de domaine. Il a été conservé tel quel.
- **urlscan.io** — un service de sécurité reconnu, utilisé par la communauté internationale. Conservé également.

**Un fournisseur posait effectivement problème :**

- **ip-api.com** était interrogé en **HTTP**, sans chiffrement (ligne 30 de `config.py`). Son offre gratuite n'existe qu'en clair. Au-delà du chiffrement, il confondait deux choses différentes : qui possède une adresse et où elle se trouve.

**Un point n'était pas une API mais une source d'imprécision :**

- La résolution DNS passait par le **résolveur de votre propre machine**. Le résultat dépendait donc de votre fournisseur d'accès. Deux personnes analysant le même domaine pouvaient obtenir des adresses différentes, sans qu'aucune des deux ne soit fausse. Cela ne se voit pas, mais cela rend une analyse non reproductible.

**Et il manquait l'essentiel :**

- Aucune source ne donnait le verdict de moteurs de sécurité. L'outil pouvait décrire un domaine en détail sans jamais dire qu'il était signalé comme dangereux.

---

## 3. Les sources utilisées désormais

Chaque source répond à une question précise. Elles sont de deux catégories.

### 3.1 Sources sans clé — elles fonctionnent dès maintenant

| # | Source | Reconnaissance | Ce qu'elle apporte |
|---|---|---|---|
| 1 | **RDAP** | Norme officielle de l'ICANN | Qui a enregistré le domaine, quand, jusqu'à quand. Donnée de registre, officielle |
| 2 | **Cloudflare 1.1.1.1** et **Google 8.8.8.8** | Deux des plus grands résolveurs DNS du monde | Les adresses réelles, vues par deux résolveurs indépendants, en HTTPS |
| 3 | **RDAP pour les adresses IP** | Norme ICANN, publiée par ARIN, RIPE, APNIC | Le titulaire **enregistré** du bloc d'adresses — un fait vérifiable |
| 4 | **IPinfo** | Prestataire professionnel de données IP | La localisation **estimée** : pays, ville, opérateur, ASN |
| 5 | **Qualys SSL Labs** | La référence mondiale pour noter un serveur chiffré | Une note de **A+ à F** sur la qualité de la configuration |
| 6 | **Journaux de transparence des certificats** (crt.sh) | Dispositif public obligatoire depuis 2018 | Les sous-domaines révélés par les certificats émis |
| 7 | **urlscan.io** | Service de sécurité reconnu | Ce qui a été réellement observé sur le domaine |

### 3.2 Source facultative — à activer pour aller plus loin

| # | Source | Reconnaissance | Ce qu'elle apporte | Activation |
|---|---|---|---|---|
| 8 | **VirusTotal** | La référence mondiale de la réputation | Le verdict de **plus de 70 moteurs antivirus**. C'est la seule source capable de **confirmer** un danger | `VIRUSTOTAL_KEY` |

> **VirusTotal est gratuit** pour cet usage (500 analyses par jour). Son absence n'empêche rien : la fiche l'indique honnêtement au lieu d'inventer un résultat. `[À COMPLÉTER : créer un compte sur virustotal.com, puis coller la clé dans le fichier .env à la ligne VIRUSTOTAL_KEY]`

---

## 4. Trois corrections d'exactitude trouvées en chemin

Ces points ne figuraient dans aucune demande. Ils ont été découverts en testant, et chaque fois la version précédente produisait un résultat faux.

### 4.1 Les résolveurs DNS divergents ne sont pas une anomalie

Les tests ont montré que Cloudflare et Google renvoient des **adresses différentes** pour google.com et github.com. Le réflexe aurait été d'en faire un signal d'alerte.

C'est faux : tout site réparti sur plusieurs serveurs renvoie des adresses différentes selon l'endroit d'où on l'interroge. En faire un signal aurait fait **crier l'outil au loup sur Google et GitHub**, c'est-à-dire sur les domaines les plus légitimes qui existent.

Le signal retenu est donc uniquement le **désaccord sur l'existence** du nom : l'un des résolveurs affirme que le domaine existe, l'autre qu'il n'existe pas. Cela, en revanche, mérite d'être relevé.

### 4.2 Le registre n'est pas toujours l'exploitant

Pour l'adresse `1.1.1.1`, le registre officiel déclare comme titulaire **« APNIC Research and Development »**. C'est exact — le bloc a bien été alloué au registre — mais un utilisateur qui lit cela comprend « cette adresse appartient à un organisme asiatique inconnu », alors qu'il s'agit de **Cloudflare**.

La fiche affiche désormais l'exploitant réel, tout en conservant l'information de registre.

### 4.3 Un signalement d'antivirus ne se compense pas

C'est le défaut le plus sérieux trouvé. Le score additionnait les points positifs et négatifs. Résultat : un domaine signalé par cinq moteurs antivirus obtenait **« risque modéré »**, parce qu'il était ancien, bien chiffré et hébergé chez un professionnel. Ces bonnes notes effaçaient le signalement.

C'est exactement le profil d'un escroc soigneux. Un **plancher** a donc été posé : un signalement confirmé impose le niveau élevé, quels que soient les points favorables par ailleurs.

---

## 5. Résultats compréhensibles par un non-informaticien

La fiche s'ouvre maintenant sur une conclusion en français courant, **avant** la jauge technique. Elle répond à trois questions dans l'ordre :

1. **Est-ce dangereux ?** — une phrase, sans aucun terme technique
2. **Qu'est-ce que je fais ?** — une consigne concrète
3. **Pourquoi ?** — ce qui pose problème, ce qui rassure

**Exemple, sur un domaine sain :**

> **Aucun signe défavorable détecté**
> Les contrôles effectués sur github.com n'ont révélé aucun élément préoccupant : le domaine existe depuis longtemps, sa connexion est chiffrée et il n'est signalé nulle part.
>
> **Ce qu'il faut faire** — Cela ne garantit pas l'honnêteté de son propriétaire. Restez vigilant si l'on vous demande de payer par un moyen inhabituel, ou de communiquer des codes reçus par message.

**Exemple, sur une adresse qui n'existe pas :**

> **Ce site présente un danger sérieux**
> L'adresse ce-site-n-existe-pas.com ne correspond à aucun site : ce domaine n'est enregistré par personne. Un message qui porte ce lien est nécessairement une invention.

Chaque fiche comporte également un volet repliable, **« ce que cette analyse ne permet pas d'affirmer »**. Il est indispensable : sans lui, quelqu'un qui lit « aucun signe défavorable » alors que la moitié des sources a échoué serait faussement rassuré. Il rappelle aussi systématiquement qu'**un site peut être techniquement irréprochable et servir à escroquer** — l'analyse porte sur la technique, pas sur la moralité du propriétaire.

Le vocabulaire est vérifié automatiquement : les tests refusent les mots « RDAP », « TLS », « DNS », « API », « ASN », « HTTP », « registrar » ou « SSL » dans la conclusion et dans le conseil.

Le détail technique reste disponible juste en dessous, pour qui le cherche.

---

## 6. Vérification

Un fichier de tests a été ajouté : `test_sources.py`. Il contient **55 vérifications**, réparties en deux catégories :

- **hors ligne** — la logique de décision : quelle conclusion pour quels signaux, quelle gravité, quel texte. Ce sont ces tests qui protègent contre les régressions, car ils ne dépendent ni du réseau ni d'un service tiers.
- **en ligne** — l'interrogation réelle des sources. Indispensables pour détecter qu'un prestataire a changé son format, mais susceptibles d'échouer sans qu'il y ait de bug : un service gratuit peut être momentanément indisponible.

Une fiche d'analyse complète prend de 3 à 30 secondes, selon que le domaine a déjà été noté récemment par SSL Labs.

---

## 7. Ce qu'il reste à faire de votre côté

Deux points, tous deux facultatifs.

1. **Activer VirusTotal** (recommandé). C'est la seule source capable de **confirmer** qu'un site est dangereux, et non simplement de repérer des anomalies de configuration. Compte gratuit, 500 analyses par jour. `[À COMPLÉTER : coller la clé dans .env à la ligne VIRUSTOTAL_KEY]`

2. **Mettre à jour le site en ligne.** Les modifications sont locales. Le déploiement sur Railway se fait par un envoi sur GitHub ; dites-le-moi quand vous voulez que je le fasse.

Rien d'autre n'est nécessaire : les sept autres sources fonctionnent sans compte ni clé.

---

## 8. Une réserve à connaître

**crt.sh est un service gratuit et « au mieux ».** Il répond souvent en erreur lorsqu'il est surchargé — c'est arrivé pendant les tests, à plusieurs reprises. L'outil réessaie trois fois, puis signale honnêtement que la recherche n'a pas abouti, au lieu de laisser croire que le domaine n'a aucun sous-domaine. C'est la seule source de la liste dans ce cas.
