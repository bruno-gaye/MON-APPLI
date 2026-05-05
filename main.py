"""
Simulation complète du système de vote électronique sécurisé
=============================================================
Acteurs : Électeur · Autorité Électorale · Serveur de Vote
Sécurité : RSA-2048 · SHA-256 · RSA-PSS · RSA-OAEP · PKI
"""

import json
from pki import AutoriteElectorale, generer_paire_cles
from electeur import Electeur
from serveur import ServeurDeVote


def afficher_titre(texte: str):
    print(f"\n{'═'*55}")
    print(f"  {texte}")
    print(f"{'═'*55}")


def afficher_resultats(resultats: dict):
    print(f"\n  Élection    : {resultats['election']}")
    print(f"  Total votes : {resultats['total_votes']}")
    print(f"\n  Résultats :")
    for candidat, nb in resultats["resultats"].items():
        pct = resultats["pourcentages"].get(candidat, 0)
        barre = "█" * int(pct / 5)
        print(f"    {candidat:<20} {nb:>3} votes  {pct:>6.2f}%  {barre}")


def main():
    afficher_titre("SYSTÈME DE VOTE ÉLECTRONIQUE SÉCURISÉ")

    # ──────────────────────────────────────────
    # PHASE 1 : Initialisation de l'infrastructure
    # ──────────────────────────────────────────
    afficher_titre("PHASE 1 — Initialisation PKI")

    autorite = AutoriteElectorale("Commission Électorale Nationale")

    # Génération des clés du serveur
    cle_privee_serveur, cle_publique_serveur = generer_paire_cles()
    print("[PKI] Paire de clés RSA-2048 du serveur générée.")

    serveur = ServeurDeVote("Élection Présidentielle 2025", autorite)
    serveur.configurer_cles(cle_privee_serveur, cle_publique_serveur)

    # ──────────────────────────────────────────
    # PHASE 2 : Enregistrement des électeurs
    # ──────────────────────────────────────────
    afficher_titre("PHASE 2 — Enregistrement des électeurs")

    electeurs_data = [
        ("electeur_001", "Alice Diallo"),
        ("electeur_002", "Mamadou Ndiaye"),
        ("electeur_003", "Fatou Sène"),
        ("electeur_004", "Ibrahima Fall"),
    ]

    electeurs = []
    for id_e, nom in electeurs_data:
        cle_priv, cle_pub = generer_paire_cles()
        autorite.enregistrer_electeur(id_e, cle_pub)
        electeurs.append(Electeur(id_e, cle_priv, cle_pub))

    # ──────────────────────────────────────────
    # PHASE 3 : Vote des électeurs
    # ──────────────────────────────────────────
    afficher_titre("PHASE 3 — Vote")

    scenarios = [
        (electeurs[0], "Candidat A"),
        (electeurs[1], "Candidat B"),
        (electeurs[2], "Candidat A"),
        (electeurs[3], "Candidat A"),
    ]

    for electeur, choix in scenarios:
        print(f"\n→ {electeur.id_electeur} vote pour '{choix}'")
        bulletin = electeur.preparer_bulletin(choix, cle_publique_serveur)
        reponse = serveur.recevoir_bulletin(bulletin)
        statut = "✅ ACCEPTÉ" if reponse["accepte"] else "❌ REJETÉ"
        print(f"  Serveur : {statut} — {reponse['raison']}")

    # ──────────────────────────────────────────
    # PHASE 4 : Test double-vote (fraude)
    # ──────────────────────────────────────────
    afficher_titre("PHASE 4 — Tentative de fraude (double vote)")

    print(f"\n→ {electeurs[0].id_electeur} tente de voter une 2e fois...")
    bulletin_fraude = electeurs[0].preparer_bulletin("Candidat B", cle_publique_serveur)
    reponse_fraude = serveur.recevoir_bulletin(bulletin_fraude)
    statut = "✅ ACCEPTÉ" if reponse_fraude["accepte"] else "❌ REJETÉ"
    print(f"  Serveur : {statut} — {reponse_fraude['raison']}")

    # ──────────────────────────────────────────
    # PHASE 5 : Dépouillement
    # ──────────────────────────────────────────
    afficher_titre("PHASE 5 — Dépouillement officiel")

    resultats = serveur.depouiller()
    afficher_resultats(resultats)

    # ──────────────────────────────────────────
    # PHASE 6 : Journal d'audit
    # ──────────────────────────────────────────
    serveur.afficher_journal()

    afficher_titre("SIMULATION TERMINÉE")
    print("  Propriétés garanties :")
    print("  ✔ Authenticité      → Signature RSA-PSS par clé privée")
    print("  ✔ Intégrité         → Hash SHA-256 du vote")
    print("  ✔ Confidentialité   → Chiffrement RSA-OAEP")
    print("  ✔ Non-répudiation   → PKI + certificats")
    print("  ✔ Unicité du vote   → Registre anti double-vote")
    print("  ✔ Transparence      → Journal d'audit public\n")


if __name__ == "__main__":
    main()
