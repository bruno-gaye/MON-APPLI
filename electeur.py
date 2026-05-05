"""
Module Électeur
Gère la signature numérique du vote et son chiffrement avant envoi au serveur.
"""

import hashlib
import json
import base64
import os
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def hacher_vote(choix: str) -> str:
    """
    Calcule le hash SHA-256 du choix de vote.
    Garantit l'intégrité : toute modification change le hash.
    """
    return hashlib.sha256(choix.encode('utf-8')).hexdigest()


def signer_vote(cle_privee, hash_vote: str) -> str:
    """
    Signe le hash du vote avec la clé privée RSA de l'électeur.
    Garantit l'authenticité et la non-répudiation.

    Processus :
        clé_privée + hash_vote → signature numérique
    """
    signature_bytes = cle_privee.sign(
        hash_vote.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature_bytes).decode('utf-8')


def chiffrer_vote(cle_publique_serveur, paquet: dict) -> str:
    """
    Chiffrement HYBRIDE (pratique réelle) :
      1. Génère une clé AES-256 aléatoire (clé de session)
      2. Chiffre le paquet JSON avec AES-GCM (rapide, authentifié)
      3. Chiffre la clé AES avec RSA-OAEP (sécurité asymétrique)
      4. Envoie les deux dans un seul paquet base64

    Avantages : supporte des messages de taille arbitraire,
                cumule la vitesse d'AES et la sécurité de RSA.
    """
    message = json.dumps(paquet).encode('utf-8')

    # Étape 1 : clé AES-256 aléatoire + nonce GCM
    cle_aes = os.urandom(32)
    nonce = os.urandom(12)

    # Étape 2 : chiffrement AES-GCM
    aesgcm = AESGCM(cle_aes)
    ciphertext = aesgcm.encrypt(nonce, message, None)

    # Étape 3 : chiffrement de la clé AES avec RSA-OAEP
    cle_aes_chiffree = cle_publique_serveur.encrypt(
        cle_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Étape 4 : assemblage du paquet final
    paquet_final = {
        "cle_aes_chiffree": base64.b64encode(cle_aes_chiffree).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }
    return base64.b64encode(json.dumps(paquet_final).encode()).decode('utf-8')


class Electeur:
    """
    Représente un électeur avec son identité et sa paire de clés.
    Il peut préparer et envoyer un bulletin chiffré et signé.
    """

    def __init__(self, id_electeur: str, cle_privee, cle_publique):
        self.id_electeur = id_electeur
        self._cle_privee = cle_privee      # Gardée secrète
        self.cle_publique = cle_publique
        print(f"[ÉLECTEUR] '{id_electeur}' initialisé avec ses clés RSA.")

    def preparer_bulletin(self, choix: str, cle_publique_serveur) -> str:
        """
        Prépare un bulletin sécurisé en 3 étapes :
          1. Hash du choix (intégrité)
          2. Signature du hash (authenticité + non-répudiation)
          3. Chiffrement du paquet complet (confidentialité)

        Retourne le bulletin chiffré (string base64).
        """
        print(f"\n[ÉLECTEUR] Préparation du bulletin pour '{self.id_electeur}'...")

        # Étape 1 — Hachage
        hash_vote = hacher_vote(choix)
        print(f"  ✔ Hash SHA-256 : {hash_vote[:32]}...")

        # Étape 2 — Signature numérique
        signature = signer_vote(self._cle_privee, hash_vote)
        print(f"  ✔ Signature RSA-PSS : {signature[:40]}...")

        # Étape 3 — Construction du paquet
        paquet = {
            "id_electeur": self.id_electeur,
            "hash_vote": hash_vote,
            "choix": choix,           # Dans un vrai système → chiffrement homomorphe
            "signature": signature,
            "timestamp": datetime.utcnow().isoformat()
        }

        # Étape 4 — Chiffrement RSA-OAEP
        bulletin_chiffre = chiffrer_vote(cle_publique_serveur, paquet)
        print(f"  ✔ Vote chiffré RSA-OAEP : {bulletin_chiffre[:40]}...")
        print(f"[ÉLECTEUR] Bulletin prêt à être envoyé.")

        return bulletin_chiffre
