"""
Module PKI - Infrastructure à Clés Publiques
Gère la génération des paires de clés RSA et la simulation des certificats.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import json
import base64
from datetime import datetime


def generer_paire_cles():
    """Génère une paire de clés RSA 2048 bits."""
    cle_privee = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    cle_publique = cle_privee.public_key()
    return cle_privee, cle_publique


def serialiser_cle_publique(cle_publique) -> str:
    """Sérialise une clé publique en PEM (format texte)."""
    pem = cle_publique.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')


def deserialiser_cle_publique(pem_str: str):
    """Reconstruit une clé publique depuis son format PEM."""
    return serialization.load_pem_public_key(
        pem_str.encode('utf-8'),
        backend=default_backend()
    )


def creer_certificat(id_electeur: str, cle_publique, autorite_id: str) -> dict:
    """
    Simule un certificat d'identité pour un électeur.
    Dans un vrai système, ce serait un certificat X.509 signé par l'AC.
    """
    return {
        "id_electeur": id_electeur,
        "cle_publique_pem": serialiser_cle_publique(cle_publique),
        "delivre_par": autorite_id,
        "date_emission": datetime.utcnow().isoformat(),
        "valide": True
    }


class AutoriteElectorale:
    """
    Représente l'autorité électorale (AC racine).
    Elle enregistre les électeurs et délivre leurs certificats.
    """

    def __init__(self, nom: str):
        self.nom = nom
        self.registre_certificats = {}   # id_electeur → certificat
        self.registre_votes = set()      # id_electeur ayant déjà voté
        print(f"[PKI] Autorité électorale '{self.nom}' initialisée.")

    def enregistrer_electeur(self, id_electeur: str, cle_publique) -> dict:
        """Enregistre un électeur et lui délivre un certificat."""
        if id_electeur in self.registre_certificats:
            raise ValueError(f"Électeur '{id_electeur}' déjà enregistré.")

        cert = creer_certificat(id_electeur, cle_publique, self.nom)
        self.registre_certificats[id_electeur] = cert
        print(f"[PKI] Certificat délivré pour '{id_electeur}'.")
        return cert

    def verifier_certificat(self, id_electeur: str) -> bool:
        """Vérifie qu'un électeur possède un certificat valide."""
        cert = self.registre_certificats.get(id_electeur)
        return cert is not None and cert["valide"]

    def a_deja_vote(self, id_electeur: str) -> bool:
        """Vérifie si l'électeur a déjà exercé son droit de vote."""
        return id_electeur in self.registre_votes

    def marquer_comme_vote(self, id_electeur: str):
        """Marque l'électeur comme ayant voté (anti double-vote)."""
        self.registre_votes.add(id_electeur)

    def obtenir_cle_publique(self, id_electeur: str):
        """Retourne la clé publique d'un électeur enregistré."""
        cert = self.registre_certificats.get(id_electeur)
        if not cert:
            raise ValueError(f"Électeur '{id_electeur}' introuvable.")
        return deserialiser_cle_publique(cert["cle_publique_pem"])
