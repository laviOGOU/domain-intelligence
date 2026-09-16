# Domain Intelligence

Application **Python** (Flask) qui évalue la fiabilité d'un nom de domaine :
saisie d'un domaine → interrogation d'API externes → fiche de résultats →
niveau de risque argumenté → enregistrement en base → historique.

Projet pédagogique. Aucune clé API n'est nécessaire.

---

## 1. Lancer l'application

Double-clique sur **`lancer_app.bat`**, ou en ligne de commande :

```bash
cd "D:\PYTHON\Domain intelligent"
.venv\Scripts\python.exe app.py
```

Puis ouvre **http://127.0.0.1:5001**

La fenêtre du terminal doit rester ouverte (la fermer arrête le serveur).
Le serveur écoute uniquement sur `127.0.0.1` : il n'est pas accessible depuis
le réseau.

---

## 2. Les 7 fonctions demandées

| # | Fonction | Où c'est implémenté |
|---|---|---|
| 1 | Saisie d'un nom de domaine | `web/templates/index.html` (formulaire) + `analyzer.normalize_domain()` |
| 2 | Interrogation d'API externes | `providers/rdap.py`, `providers/network.py` |
| 3 | Récupération des informations | `analyzer.analyze()` (appels parallèles) |
| 4 | Affichage sous forme de fiche | `web/templates/index.html` |
| 5 | Attribution d'un niveau de risque | `risk.py` (score sur 100 → LOW / MEDIUM / HIGH) |
| 6 | Enregistrement dans Supabase | `db.py` (`save_analysis`) |
| 7 | Affichage de l'historique | `web/templates/history.html` + `db.list_analyses()` |

Exemple de fiche produite :

```
Domain : micros0ft.com
Registrar : GoDaddy.com, LLC
Country : — (hébergement non résolu)
IP : —
Domain age : 28 ans et 8 mois (10486 jours)
Risk : MEDIUM (score 45/100)
Analyse effectuée le : 2026-09-15 18:39:50
```

---

## 3. API externes utilisées (aucune clé requise)

| Source | Ce qu'elle fournit |
|---|---|
| **RDAP** — `rdap.org/domain/<domaine>` | Registrar, dates de création / expiration / modification, statuts du registre, serveurs de noms. Successeur normalisé de WHOIS, en JSON |
| **ip-api.com** | Pays, ville, opérateur (ISP), organisation, ASN, indicateur d'hébergement et de proxy, pour l'IP du domaine |
| **DNS (stdlib + dnspython)** | Adresses IPv4, enregistrements NS / MX / TXT |
| **TLS direct (stdlib ssl)** | Validité du certificat, émetteur, date d'expiration |

Politique de panne : si une source est injoignable, l'analyse continue et la
limite est affichée dans la section « Limites de cette analyse ». Les appels
sont lancés en parallèle (analyse complète en 2 à 4 secondes).

---

## 4. Calcul du risque

Score sur 100, borné à `[0 ; 100]` :

| Points | Signal |
|---|---|
| +40 | Domaine créé il y a moins de 30 jours |
| +40 | Domaine non enregistré au registre |
| +30 | Créé il y a moins de 90 jours |
| +25 | HTTPS absent ou certificat invalide |
| +20 | Le domaine ne résout pas (aucune IP) |
| +20 | Domaine expiré |
| +18 | Créé il y a moins d'un an |
| +15 | Extension à risque (.tk, .ml, .top, .click, .xyz, .zip…) |
| +12 | Expire dans moins de 60 jours |
| +10 | Termes sensibles dans le nom (login, verify, secure, account…) |
| +10 | Redirection vers un autre domaine |
| +10 | IP signalée comme proxy / VPN |
| +8 | Registrar non publié |
| +8 | Nom contenant 4 chiffres ou plus |
| +6 | Nom contenant 3 tirets ou plus |
| +5 | Date de création non publiée |
| −10 | Plus de 10 ans d'existence **et** HTTPS valide |

Niveaux : **LOW** < 25 · **MEDIUM** 25–54 · **HIGH** ≥ 55 (seuils réglables
dans `.env`).

Deux garde-fous importants :

- **Une panne de notre côté n'est pas un risque.** Si le registre RDAP est
  injoignable (quota dépassé, réseau), le score ne pénalise pas le domaine :
  la limite est signalée à 0 point. Sans cette règle, le même domaine pouvait
  passer de « MEDIUM 45 » à « HIGH 63 » selon la disponibilité du réseau.
- **Pas de double comptage.** Pour un domaine non enregistré, les tests DNS et
  HTTPS échouent forcément : ils ne sont pas comptés en plus.

Les règles sont volontairement lisibles et **affichées dans la fiche** : l'analyste
voit pourquoi un domaine est jugé risqué, il ne subit pas une note opaque.

---

## 5. Supabase

### Ce qui est en place

L'application est **connectée** au projet Supabase existant (`podqwwqjakrybkdmejxa`,
région eu-west-1, table `domain_analyses`). L'historique lit et écrit réellement
en base : la bannière en bas de page affiche `SUPABASE`.

Les deux clés sont dans `.env` (jamais versionné) :

| Variable | Rôle |
|---|---|
| `SUPABASE_URL` | adresse du projet |
| `SUPABASE_KEY` | clé **anon** — clé publique prévue pour un client |
| `SUPABASE_SERVICE_KEY` | clé **service** — utilisée ici en secours (voir ci-dessous) |

### Pourquoi la clé service est utilisée

La table `domain_analyses` a la **RLS activée sans politique** pour la clé `anon`.
Conséquence mesurée :

- l'insertion est refusée (`42501 new row violates row-level security policy`) ;
- la lecture ne renvoie **aucune erreur mais 0 ligne** — un historique
  silencieusement vide, ce qui est plus trompeur qu'un échec franc.

En attendant, l'application utilise donc `SUPABASE_SERVICE_KEY` pour toutes les
opérations. Elle reste **côté serveur** : le navigateur ne la reçoit jamais
(toutes les requêtes Supabase partent de `db.py`, jamais du JavaScript).

C'est une solution de dépannage, pas une configuration cible : la clé service
contourne toutes les règles de sécurité.

### Remettre les choses d'aplomb (recommandé, 30 secondes)

Deux méthodes, au choix.

**Méthode 1 — éditeur SQL du tableau de bord**

Ouvre <https://supabase.com/dashboard/project/podqwwqjakrybkdmejxa/sql/new>,
colle le contenu de `supabase_setup.sql`, clique sur **Run**.
Le script ajoute les politiques RLS et les colonnes complémentaires ; il est
réexécutable sans erreur.

**Méthode 2 — ligne de commande**

1. Crée un jeton sur <https://supabase.com/dashboard/account/tokens>
2. Ajoute-le dans `.env` : `SUPABASE_ACCESS_TOKEN=sbp_...`
3. Lance :

```bash
.venv\Scripts\python.exe init_supabase.py
```

Une fois les politiques en place, **supprime la ligne `SUPABASE_SERVICE_KEY`**
de `.env` et redémarre : l'application repasse sur la clé `anon`, qui est la clé
prévue pour ce type d'usage.

### Schéma de la table

Table minimale telle qu'elle existe aujourd'hui :

| Colonne | Contenu |
|---|---|
| `id` | identifiant auto |
| `domain` | domaine analysé |
| `registrar` | bureau d'enregistrement |
| `country` | pays d'hébergement |
| `ip` | première adresse IPv4 |
| `created_date` | date de création du domaine (d'où l'âge est recalculé) |
| `risk` | `LOW` / `MEDIUM` / `HIGH` |
| `analyzed_at` | horodatage de l'analyse |

`supabase_setup.sql` ajoute en option `risk_score`, `risk_factors`, `payload`
(fiche complète), `tld`, `asn`, `isp`, `https_ok`, `expires_at`, `risk_summary`.
**L'application n'a pas besoin de ces colonnes** : `db.py` envoie la fiche
complète et retire automatiquement celles que la table ne possède pas
(fonction `_insert_adaptive`), en le signalant dans le journal.

> Les politiques RLS du script sont volontairement ouvertes (projet
> mono-utilisateur avec la clé `anon`). En production, on restreindrait à
> `authenticated` avec une colonne `user_id`.

### Garantie d'enregistrement — aucune analyse perdue

Toute analyse doit se retrouver dans Supabase. Si l'écriture échoue pour une
raison **passagère** (réseau coupé, DNS, délai dépassé), le traitement est le
suivant, entièrement automatique :

1. l'écriture est **retentée** (`SUPABASE_RETRIES`, 3 tentatives par défaut,
   avec attente croissante) ;
2. en cas d'échec persistant, l'analyse est placée dans une **file d'attente**
   locale, `storage/pending.json` — elle n'est pas perdue ;
3. la file est **renvoyée automatiquement** vers Supabase au démarrage de
   l'application et à chaque nouvelle analyse (`db.flush_pending()`) ;
4. un contrôle d'idempotence (même domaine + même horodatage) empêche tout
   doublon lors du renvoi.

L'interface signale l'état : bandeau « Analyse mise en attente » avec le nombre
d'analyses en file, et compteur `En attente` dans la bannière de démarrage.

En revanche, une erreur **définitive** (clé refusée, RLS fermée, table absente)
n'est pas mise en file : elle est affichée telle quelle, car la répéter ne
servirait à rien — c'est la configuration qu'il faut corriger.

Rapatrier d'anciennes analyses restées en local :

```bash
.venv\Scripts\python.exe migrer_local_vers_supabase.py
```

Le script ignore ce qui est déjà en base, archive le fichier local
(`storage/history_avant_migration_*.json`) au lieu de le supprimer, et ne vide
le stockage local que si **tout** a été migré.

---

## 6. API JSON (pour un script ou le rapport)

| Méthode | Route | Description |
|---|---|---|
| GET | `/api/analyze?domain=example.com` | Analyse et enregistre |
| GET | `/api/analyze?domain=example.com&save=0` | Analyse sans enregistrer |
| GET | `/api/history?limit=20&q=github` | Historique |
| GET | `/api/analysis/<id>` | Fiche complète |
| DELETE | `/api/analysis/<id>` | Supprime une analyse |
| GET | `/api/status` | Backend actif + compteurs |

```bash
curl "http://127.0.0.1:5001/api/analyze?domain=example.com"
```

---

## 7. Structure du projet

```
Domain intelligent/
├── app.py                  application Flask (routes web + API JSON)
├── analyzer.py             orchestration : normalisation, appels parallèles, fiche
├── risk.py                 moteur de score (règles + niveaux)
├── db.py                   persistance : Supabase ou stockage local
├── config.py               configuration (.env) et seuils
├── providers/
│   ├── rdap.py             interrogation RDAP (registrar, dates, statuts)
│   └── network.py          DNS, géolocalisation IP, HTTPS, certificat TLS
├── web/
│   ├── templates/          base, index (fiche), history, 404
│   └── static/             css/style.css, js/app.js
├── supabase_setup.sql      création de la table + politiques RLS
├── migrer_local_vers_supabase.py  rapatrie les analyses du stockage local
├── .env.example            modèle de configuration
├── requirements.txt        dépendances
├── lancer_app.bat          lancement Windows
└── storage/                historique local (si Supabase non configuré)
```

---

## 8. Limites connues

- **RDAP n'est pas exhaustif** : certains registres ne le publient pas (certaines
  extensions africaines notamment). La fiche l'indique alors explicitement.
- **`rdap.org` limite le débit.** Une rafale d'analyses peut déclencher un
  « 429 » ; l'application le signale et le score reste honnête (voir § 4).
- **Le pays affiché est celui de l'hébergement** (l'IP), pas celui du titulaire :
  le titulaire est presque toujours masqué pour cause de RGPD. Le pays du
  registrar est conservé séparément dans la fiche.
- **Le score est un indice, pas un verdict.** Un domaine récent n'est pas
  forcément malveillant (beaucoup de startups le sont), et un domaine ancien
  peut avoir été détourné. L'outil sert à prioriser une vérification humaine.
- L'analyse d'un domaine n'implique aucun contact avec son serveur au-delà d'une
  requête HTTPS standard et d'une résolution DNS.
