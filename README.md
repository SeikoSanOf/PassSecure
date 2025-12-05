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
- 🖥️ **Interface graphique (GUI)**
- 📜 **Historique des modifications**

---

## 🚀 Installation

### 📦 Prérequis

- Python 3.x (si .exe non utilisé)
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

Au premier lancement, **PassSecure vous demandera de créer un mot de passe administrateur** et générera les fichiers nécessaires.

---
## 🛠️ Utilisation CLI (CLI retirer)

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

1. Moteur & Utilitaires (Backend)
   
| Fonction | Rôle |
|----------|------|
| `CryptoEngine` | Classe gérant la cryptographie (Argon2id) |
| `derive_key()` | Dérivation de la clé de chiffrement du coffre |
| `hash_admin_password()` | Hachage sécurisé du mot de passe maître |
| `try_migrate()` | Déchiffre et convertit les anciennes bases de données (v1 → v1.0.3) |
| `load_vault(fernet)` | Charge et déchiffre le JSON depuis le disque |
| `save_vault(fernet, data)` | Chiffre et sauvegarde le JSON sur le disque (écriture atomique) |
| `check_password_strength()` | Analyse la robustesse d'un mot de passe (score & feedback) |
| `ActionLogger.log()` | Enregistre les événements dans audit.log |

2. Interface Graphique (Frontend)

| Méthode | Rôle |
|----------|------|
| `PassSecureGUI` | Classe principale de l'application (hérite de ctk.CTk) |
| `__init__()()` | Initialisation, configuration du Timer d'inactivité |
| `show_auth_screen()` | Affiche l'écran de login ou de création de compte |
| `attempt_login()` | Vérifie le mot de passe et lance la migration si nécessaire |
| `show_dashboard()` | Affiche le menu principal (Sidebar + Contenu) |
| `view_passwords()` | CRUD (Lecture) : Affiche la liste des comptes avec recherche |
| `add_password_dialog()` | CRUD (Création) : Fenêtre modale pour ajouter un mot de passe |
| `_create_row() → del_act` | CRUD (Suppression) : Bouton poubelle pour supprimer une entrée |
| `view_generator()` | Génération : Interface de création de mots de passe aléatoires |
| `view_settings()` | Menu des paramètres (Export, Import, Changement MDP) |
| `view_settings() → nuke()` | Zone de danger : Suppression totale et sécurisée des données |
| `check_for_updates()` | Vérifie la dernière version sur GitHub via API |
| `logout()` | Verrouille l'application et efface la clé en mémoire |

3. Point d'entrée

| Bloc | Rôle |
|----------|------|
| `if __name__ == "__main__":` | Vérifie les permissions fichiers et lance la boucle mainloop() |

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

- Documentation dans les docstrings du code  

---

## 🌐 Communauté

- ⭐ Star le projet si vous l’aimez  
- 🐞 Signaler les bugs  
- 💡 Proposer des idées  
- 🔄 Partager vos retours  

---

⚡ **PassSecure — Votre sécurité, votre contrôle.**

