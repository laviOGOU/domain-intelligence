"""
migrer_local_vers_supabase.py — rapatrie dans Supabase les analyses restées
dans le stockage local (storage/history.json).

À utiliser une fois, après avoir configuré Supabase : les analyses effectuées
avant la configuration ne se trouvent que dans le fichier local.

    .venv\\Scripts\\python.exe migrer_local_vers_supabase.py

Le script est sans risque : il vérifie d'abord si chaque analyse est déjà
présente dans Supabase (même domaine + même horodatage), l'ignore dans ce cas,
et archive le fichier local au lieu de le supprimer.
"""
import json
import logging
import shutil
import sys
from datetime import datetime, timezone

import config
import db

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s | %(levelname)-8s | %(message)s",
                    datefmt="%H:%M:%S")


def main() -> int:
    if not config.supabase_configured():
        print("Supabase n'est pas configuré dans .env — rien à migrer.")
        return 1

    client = db._effective_client()
    if client is None:
        print("Client Supabase indisponible :", db._client_error or db._service_error)
        return 1

    local = db._read_local()
    if not local:
        print("Le stockage local est vide : toutes les analyses sont déjà dans Supabase.")
        return 0

    print(f"{len(local)} analyse(s) dans le stockage local.\n")

    migrees, ignorees, echecs = [], [], []
    for record in local:
        domaine = record.get("domain") or "(sans nom)"
        if db._deja_en_base(client, record):
            ignorees.append(domaine)
            print(f"  = {domaine:38s} déjà présente dans Supabase, ignorée")
            continue
        try:
            resultat = db._insert_result(client, db._to_row(record),
                                         via_service=bool(config.SUPABASE_SERVICE_KEY))
            migrees.append(domaine)
            print(f"  + {domaine:38s} migrée (id {resultat.get('id')})")
        except Exception as exc:                                  # noqa: BLE001
            echecs.append((domaine, str(exc)))
            print(f"  ! {domaine:38s} échec : {exc}")

    print()
    print(f"Résultat : {len(migrees)} migrée(s), {len(ignorees)} déjà présente(s), "
          f"{len(echecs)} échec(s).")

    if migrees and not echecs:
        horodatage = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        sauvegarde = config.STORAGE_DIR / f"history_avant_migration_{horodatage}.json"
        shutil.copy2(config.LOCAL_HISTORY_FILE, sauvegarde)
        db._write_local([])
        print(f"Stockage local vidé (tout est dans Supabase).")
        print(f"Sauvegarde conservée : {sauvegarde.name}")
        return 0

    if echecs:
        print("Le stockage local est conservé : certaines analyses n'ont pas pu être migrées.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
