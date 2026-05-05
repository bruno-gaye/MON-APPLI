"""
Module Serveur de Vote
Reçoit les bulletins chiffrés, les vérifie et procède au dépouillement sécurisé.
"""

import json
import base64
from datetime import datetime
from collections import defaultdict

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def verifier_signature(cle_publique_electeur, hash_vote: str, signature_b64: str) -> bool:
    """
    Vérifie la signature numérique du vote.
    Retourne True si la signature est valide (authentique + intègre).
    """
    try:
        signature_bytes = base64.b64decode(signature_b64)
        cle_publique_electeur.verify(
            signature_bytes,
            hash_vote.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


class ServeurDeVote:
    """
    Cœur du système de vote.
    Responsabilités :
      - Déchiffrer les bulletins reçus
      - Vérifier les signatures et l'éligibilité
      - Stocker les votes de manière sécurisée
      - Procéder au dépouillement
    """

    def __init__(self, nom_election: str, autorite: object):
        self.nom_election = nom_election
        self.autorite = autorite               # Référence à l'AutoriteElectorale
        self._cle_privee = None                # Clé privée du serveur (déchiffrement)
        self.cle_publique = None               # Clé publique partagée aux électeurs
        self.urne = []                         # Bulletins acceptés (chiffrés)
        self.journal_audit = []                # Journal d'audit (sans données personnelles)
        print(f"[SERVEUR] Serveur de vote '{nom_election}' prêt.")

    def configurer_cles(self, cle_privee, cle_publique):
        """Injecte la paire de clés du serveur."""
        self._cle_privee = cle_privee
        self.cle_publique = cle_publique
        print("[SERVEUR] Clés RSA configurées.")

    def _dechiffrer_bulletin(self, bulletin_chiffre_b64: str) -> dict:
        """
        Déchiffre un bulletin hybride (RSA-OAEP + AES-GCM) :
          1. Déchiffre la clé AES avec la clé privée RSA du serveur
          2. Déchiffre le message avec AES-GCM
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        paquet_final = json.loads(base64.b64decode(bulletin_chiffre_b64))

        # Étape 1 : déchiffrement RSA → clé AES
        cle_aes = self._cle_privee.decrypt(
            base64.b64decode(paquet_final["cle_aes_chiffree"]),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Étape 2 : déchiffrement AES-GCM → message clair
        nonce = base64.b64decode(paquet_final["nonce"])
        ciphertext = base64.b64decode(paquet_final["ciphertext"])
        aesgcm = AESGCM(cle_aes)
        message_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(message_bytes.decode('utf-8'))

    def recevoir_bulletin(self, bulletin_chiffre_b64: str) -> dict:
        """
        Traite un bulletin entrant :
          1. Déchiffrement
          2. Vérification du certificat électeur
          3. Vérification anti double-vote
          4. Vérification de la signature numérique
          5. Stockage dans l'urne
        """
        resultat = {"accepte": False, "raison": ""}
        print("\n[SERVEUR] Réception d'un bulletin...")

        # — Étape 1 : Déchiffrement
        try:
            paquet = self._dechiffrer_bulletin(bulletin_chiffre_b64)
        except Exception as e:
            resultat["raison"] = f"Échec déchiffrement : {e}"
            self._journaliser("REJETÉ", "inconnu", resultat["raison"])
            return resultat

        id_electeur = paquet.get("id_electeur", "inconnu")
        print(f"  ✔ Bulletin déchiffré pour '{id_electeur}'.")

        # — Étape 2 : Certificat valide ?
        if not self.autorite.verifier_certificat(id_electeur):
            resultat["raison"] = "Certificat invalide ou électeur non enregistré."
            self._journaliser("REJETÉ", id_electeur, resultat["raison"])
            return resultat
        print(f"  ✔ Certificat valide.")

        # — Étape 3 : Double-vote ?
        if self.autorite.a_deja_vote(id_electeur):
            resultat["raison"] = "Double vote détecté."
            self._journaliser("REJETÉ", id_electeur, resultat["raison"])
            return resultat
        print(f"  ✔ Pas de double vote.")

        # — Étape 4 : Signature valide ?
        cle_publique_electeur = self.autorite.obtenir_cle_publique(id_electeur)
        if not verifier_signature(cle_publique_electeur, paquet["hash_vote"], paquet["signature"]):
            resultat["raison"] = "Signature numérique invalide."
            self._journaliser("REJETÉ", id_electeur, resultat["raison"])
            return resultat
        print(f"  ✔ Signature RSA-PSS vérifiée.")

        # — Étape 5 : Acceptation
        self.urne.append(paquet)
        self.autorite.marquer_comme_vote(id_electeur)
        self._journaliser("ACCEPTÉ", id_electeur, "Vote enregistré avec succès.")

        resultat["accepte"] = True
        resultat["raison"] = "Vote enregistré avec succès."
        print(f"  ✅ Vote de '{id_electeur}' accepté et mis dans l'urne.")
        return resultat

    def depouiller(self) -> dict:
        """
        Dépouillement : comptage des votes par candidat.
        Dans un système réel → déchiffrement homomorphe ou protocole multipartite.
        """
        print(f"\n[SERVEUR] ═══ DÉPOUILLEMENT ═══")
        comptage = defaultdict(int)
        for bulletin in self.urne:
            comptage[bulletin["choix"]] += 1

        total = sum(comptage.values())
        resultats = {
            "election": self.nom_election,
            "total_votes": total,
            "resultats": dict(comptage),
            "pourcentages": {
                c: round(v / total * 100, 2) for c, v in comptage.items()
            } if total > 0 else {},
            "date_depouillement": datetime.utcnow().isoformat()
        }
        return resultats

    def afficher_journal(self):
        """Affiche le journal d'audit (transparence sans vie privée)."""
        print("\n[AUDIT] ═══ JOURNAL D'AUDIT ═══")
        for entree in self.journal_audit:
            print(f"  [{entree['timestamp']}] {entree['statut']} | {entree['electeur']} | {entree['detail']}")

    def _journaliser(self, statut: str, id_electeur: str, detail: str):
        """Enregistre une entrée dans le journal d'audit."""
        self.journal_audit.append({
            "timestamp": datetime.utcnow().isoformat(),
            "statut": statut,
            "electeur": id_electeur,
            "detail": detail
        })
