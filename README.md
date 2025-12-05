# 🔐 PassSecure

**PassSecure** est un **gestionnaire de mots de passe sécurisé** en ligne de commande.  
Il chiffre vos données localement avec des algorithmes cryptographiques robustes, garantissant que **vos mots de passe ne quittent jamais votre machine**.

---

## ✨ Fonctionnalités principales

- 🔒 **Chiffrement AES-256** via Fernet (Clé dérivée par Argon2id)
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
- 🖥️ Interface graphique (GUI)
- 📜 Historique des modifications

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
git clone https://github.com/SeikoSanOf/PassSecure.git
cd PassSecure
pip install -r requirements.txt
```

Au premier lancement, **PassSecure vous demandera de créer un mot de passe administrateur** et générera les fichiers nécessaires dans `~/.passsecure/`.

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
| `-l, --list` | Afficher tous les mots de passe |
| `-r, --recherche <libelle>` | recherche un mots de passe  |
| `-s, --save <libelle> <PWD>` | Enregistrer un mot de passe |
| `-u, --update <libelle>` | Mettre à jour un mot de passe |
| `-del, --supprimer <libelle>` | Supprimer un mot de passe |
| `-i, --importer <fichier>` | Importer des mots de passe depuis un fichier |
| `-n, --nuke` | Supprimer toutes les données |
| `-g, --generate` | Générer un mot de passe |
| `-t, --taille <n>` | Taille du mot de passe aléatoire |
| `-nbm, --nb-mots <n>` | Nombre de mots pour mot de passe dictionnaire |
| `-ea, --exclure-ambigus` | Exclure caractères ambigus |
| `-d, --dictionnaire <fichier>` | Fichier dictionnaire personnalisé |
| `--check-update` | Vérifier mise à jour |
---

## 🧱 Structure du code

| Fonction | Rôle |
|----------|------|
| `request_admin_password()` | Authentification et création mot de passe admin |
| `derive_key()` | Dérivation de clé via PBKDF2-HMAC ou Argon2id |
| `generate_*()` | Génération de mots de passe |
| `*_password()` | Fonctions CRUD (ajout, suppression, modification, affichage) |
| `main()` | Point d’entrée CLI |
| `copy(text)` | Copie dans presse-papier |
| `nuke_all()` | Supprime toutes les données de manière sécurisée |

---

## 🤝 Contribuer

PassSecure est open-source. Toute contribution est la bienvenue !

```bash
# Fork du projet
git clone https://github.com/SeikoSanOf/PassSecure.git
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

- ☁️ Synchronisation cloud chiffrée (fichié déchifrable par votre unique clé)
- 🧠 Générateur de phrases de passe (mnémotechnique)  
- 🔍 Audit de sécurité interne  
- 🔄 Export vers KeePass / 1Password  
- 🔐 Support 2FA (TOTP)  
- ⚙️ Mode batch pour scripts  

---

## ⚠️ Limitations actuelles

- 📍 Local uniquement (pas de synchronisation)
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

- `python PassSecure.py --help` : aide intégrée a la version console (ancienne version)
- Documentation dans les docstrings du code  

---

## 🌐 Communauté

- ⭐ Star le projet si vous l’aimez  
- 🐞 Signaler les bugs  
- 💡 Proposer des idées  
- 🔄 Partager vos retours  

---

⚡ **PassSecure — Votre sécurité, votre contrôle.**

