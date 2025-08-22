# 🔐 PassSecure

**PassSecure** est un **gestionnaire de mots de passe sécurisé** en ligne de commande.  
Il chiffre vos données localement avec des algorithmes cryptographiques robustes, garantissant que **vos mots de passe ne quittent jamais votre machine**.

---

## ✨ Fonctionnalités principales

- 🔒 **Chiffrement AES-256** via Fernet (Clé dérivée par PBKDF2-HMAC ou Argon2id)
- 🛡️ **Authentification sécurisée** via bcrypt pour le mot de passe administrateur
- 🔐 **Intégrité de la base** : HMAC global pour détecter toute modification ou corruption
- 🎲 **Générateur de mots de passe** aléatoires ou basés sur un dictionnaire
- 📋 **Copie automatique dans le presse-papier** avec purge automatique après 20 secondes
- 🔍 **Recherche et filtrage** des mots de passe
- 📂 **Import/Export** de la base de données
- 🗑️ **Gestion complète** : ajout, modification, suppression, purge totale
- 🔧 **Interface CLI intuitive**
- 🚫 **Protection Git** automatique via `.gitignore`
- 📊 **Métadonnées KDF et versioning** pour migrations futures

---

## 🚀 Installation

### 📦 Prérequis

- Python 3.x
- Bibliothèques :

```bash
pip install cryptography>=3.4.0 bcrypt>=3.2.0 pyperclip>=1.8.0 argon2-cffi>=21.3.0
```

### 🔧 Installation et setup

```bash
git clone https://github.com/votre-utilisateur/PassSecure.git
cd PassSecure
pip install -r requirements.txt
```

Au premier lancement, **PassSecure vous demandera de créer un mot de passe administrateur** et générera les fichiers nécessaires dans `~/.secure_passwords/`.

---

## 🎲 Génération de mots de passe

### 1️⃣ Aléatoire

```bash
python PassSecure.py -g --taille 16
```
- `--exclure-ambigus` : pour éviter les caractères ambigus (O, 0, l, I, etc.)

### 2️⃣ Dictionnaire personnalisé

1. Créez un fichier texte (un mot par ligne) :

```text
securite
chiffrement
motdepasse
protection
authentification
cryptographie
developpement
ordinateur
internet
```

2. Générer un mot de passe :

```bash
python PassSecure.py -g --nb-mots 4 --dictionnaire mon_dictionnaire.txt
```

💡 Astuce : mélangez mots personnels et termes professionnels pour des mots de passe forts et mémorables.

---

## 🛠️ Utilisation CLI

| Option | Description |
|--------|-------------|
| `-l, --liste` | Afficher tous les mots de passe |
| `-r, --recherche <libelle>` | Rechercher un mot de passe |
| `-s, --supprimer <libelle>` | Supprimer un mot de passe |
| `-u, --update <libelle>` | Mettre à jour un mot de passe |
| `-i, --importer <fichier>` | Importer des mots de passe depuis un fichier |
| `-n, --nuke` | Supprimer toutes les données |
| `-g, --generate` | Générer un mot de passe |
| `--taille <n>` | Taille du mot de passe aléatoire |
| `--nb-mots <n>` | Nombre de mots pour mot de passe dictionnaire |
| `--exclure-ambigus` | Exclure caractères ambigus |
| `--dictionnaire <fichier>` | Fichier dictionnaire personnalisé |

---

## 🧱 Structure du code

| Fonction | Rôle |
|----------|------|
| `demander_admin()` | Authentification et création mot de passe admin |
| `derive_key()` | Dérivation de clé via PBKDF2-HMAC ou Argon2id |
| `generer_*()` | Génération de mots de passe |
| `*_mot_de_passe()` | Fonctions CRUD (ajout, suppression, modification, affichage) |
| `main()` | Point d’entrée CLI |
| `copy_with_clear()` | Copie dans presse-papier avec purge automatique |
| `nukeall()` | Supprime toutes les données de manière sécurisée |

---

## 🤝 Contribuer

PassSecure est open-source. Toute contribution est la bienvenue !

```bash
# Fork du projet
git clone https://github.com/votre-utilisateur/PassSecure.git
cd PassSecure

# Créer une branche
git checkout -b feature/ma-nouvelle-fonctionnalite

# Ajouter des changements
git commit -am 'Ajout: ma nouvelle fonctionnalité'

# Push et PR
git push origin feature/ma-nouvelle-fonctionnalite
```

**Types de contributions recherchées :**

- 🐛 Corrections de bugs  
- ✨ Nouvelles fonctionnalités  
- 📚 Documentation  
- 🔒 Sécurité  
- 🧪 Tests  
- 🌍 Traductions  

---

## 📋 Feuille de route

- 🖥️ Interface graphique (GUI)  
- ☁️ Synchronisation cloud chiffrée  
- 🧠 Générateur de phrases de passe (mnémotechnique)  
- 🔍 Audit de sécurité interne  
- 🔄 Export vers KeePass / 1Password  
- 🔐 Support 2FA (TOTP)  
- ⚙️ Mode batch pour scripts  
- 📜 Historique des modifications  

---

## ⚠️ Limitations actuelles

- 📍 Local uniquement (pas de synchronisation)  
- 💻 CLI uniquement (pas encore de GUI)  
- 🐍 Python requis  
- 📋 Copie presse-papier dépendante du système  

---

## 📄 Licence

MIT License – voir fichier LICENSE

---

## 🆘 Support

- 🐞 Issues GitHub pour signaler un bug  
- 💬 Discussions GitHub pour questions générales  
- 🔐 Sécurité : signaler vulnérabilités en privé  

---

## 🔗 Ressources utiles

- `python PassSecure.py --help` : aide intégrée  
- Fichiers exemples pour dictionnaire  
- Documentation dans les docstrings du code  

---

## 🌐 Communauté

- ⭐ Star le projet si vous l’aimez  
- 🐞 Signaler les bugs  
- 💡 Proposer des idées  
- 🔄 Partager vos retours  

---

⚡ **PassSecure — Votre sécurité, votre contrôle.**

