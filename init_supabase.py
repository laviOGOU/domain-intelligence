"""
init_supabase.py — Crée / met à jour la table Supabase sans passer par l'interface web.

Le script a besoin d'un **jeton d'accès personnel** Supabase (PAT), à créer ici :
    https://supabase.com/dashboard/account/tokens
puis à coller dans .env :

    SUPABASE_ACCESS_TOKEN=sbp_xxxxxxxxxxxxxxxx

Utilisation :
    .venv\\Scripts\\python.exe init_supabase.py

Pourquoi ce détour : l'exécution de SQL (DDL) n'est possible que par l'éditeur SQL
du tableau de bord ou par l'API Management, qui exige un PAT. La clé « anon » ne
permet pas de modifier un schéma. Si tu préfères, exécute simplement
supabase_setup.sql dans l'éditeur SQL : le résultat est identique.
"""
import os
import sys

import requests
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

API = "https://api.supabase.com/v1"
SQL_FILE = os.path.join(BASE_DIR, "supabase_setup.sql")


def main() -> int:
    token = os.getenv("SUPABASE_ACCESS_TOKEN", "").strip()
    project_ref = os.getenv("SUPABASE_PROJECT_REF", "").strip()

    if not project_ref:
        url = os.getenv("SUPABASE_URL", "")
        project_ref = url.replace("https://", "").split(".")[0] if url else ""

    if not token or not project_ref:
        print("Jeton ou référence de projet manquant.\n")
        print("Ajoute ces deux lignes dans .env :")
        print("  SUPABASE_ACCESS_TOKEN=sbp_...   (https://supabase.com/dashboard/account/tokens)")
        print("  SUPABASE_PROJECT_REF=xxxxxxxx    (ou laisse SUPABASE_URL, il est déduit)")
        return 1

    with open(SQL_FILE, "r", encoding="utf-8") as handle:
        sql = handle.read()

    print(f"Projet visé : {project_ref}")
    print(f"Script SQL  : {len(sql)} caractères")
    response = requests.post(
        f"{API}/projects/{project_ref}/database/query",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"query": sql},
        timeout=60,
    )

    print("HTTP", response.status_code)
    if response.status_code in (200, 201):
        print("Table créée / mise à jour avec succès.")
        try:
            rows = response.json()
            if isinstance(rows, list) and rows:
                print("Dernière instruction — colonnes présentes :")
                for row in rows[:30]:
                    print("   ", row)
        except ValueError:
            pass
        return 0

    print(response.text[:600])
    if response.status_code in (401, 403):
        print("\nJeton refusé. Vérifie qu'il commence par 'sbp_' et qu'il est actif.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
