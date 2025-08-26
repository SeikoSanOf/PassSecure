import os
import sys
import json
import base64
import bcrypt
import getpass
import secrets
import string
import pyperclip
import argparse
import tempfile
import threading
import time
import hmac
import hashlib

from argon2.low_level import hash_secret_raw, Type

try:
    import argon2
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# -------------------------
# Version & URL de maj
# -------------------------
__version__ = "1.0.0"
GITHUB_API_URL = "https://api.github.com/repos/SeikoSanOf/PassSecure/releases/latest"

# -------------------------
# Dossiers et fichiers
# -------------------------
SECURE_DIR = os.path.expanduser("~/.passsecure")
SALT_FILE = os.path.join(SECURE_DIR, "salt.bin")
ADMIN_HASH_FILE = os.path.join(SECURE_DIR, "admin_hash.txt")
DB_FILE = os.path.join(SECURE_DIR, "passwords.json")
META_FILE = os.path.join(SECURE_DIR, "meta.json")
HMAC_KEY_FILE = os.path.join(SECURE_DIR, "hmac.key")

# -------------------------
# Helpers permissions
# -------------------------
def _chmod_safe(path, mode):
    try:
        os.chmod(path, mode)
    except Exception:
        pass

def _ensure_permissions():
    if os.path.isdir(SECURE_DIR):
        _chmod_safe(SECURE_DIR, 0o700)
    for f in (SALT_FILE, ADMIN_HASH_FILE, DB_FILE, META_FILE, HMAC_KEY_FILE):
        if os.path.exists(f):
            _chmod_safe(f, 0o600)

def write_json_atomic(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp_", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        _chmod_safe(path, 0o600)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)

# -------------------------
# Salt et KDF
# -------------------------
def load_or_create_salt():
    os.makedirs(SECURE_DIR, exist_ok=True)
    if not os.path.exists(SALT_FILE):
        salt = secrets.token_bytes(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        _chmod_safe(SALT_FILE, 0o600)
    else:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
    return salt

def derive_key(password, salt, method="pbkdf2"):
    if method=="argon2" and ARGON2_AVAILABLE:
        # Argon2id en raw pour obtenir 32 bytes exacts
        key_bytes = hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=3,
            memory_cost=64*1024,
            parallelism=2,
            hash_len=32,
            type=Type.ID
        )
        return base64.urlsafe_b64encode(key_bytes)
    else:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390_000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# -------------------------
# Admin
# -------------------------
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def request_admin_password():
    os.makedirs(SECURE_DIR, exist_ok=True)
    _chmod_safe(SECURE_DIR, 0o700)

    if not os.path.exists(ADMIN_HASH_FILE):
        print("⚠️ Créez un mot de passe admin :")
        while True:
            p1 = getpass.getpass("Nouveau mot de passe : ")
            p2 = getpass.getpass("Confirmez : ")
            if p1 != p2:
                print("❌ Mots de passe différents, réessayez.")
                continue
            if not p1.strip():
                print("❌ Mot de passe vide.")
                continue
            with open(ADMIN_HASH_FILE, "w", encoding="utf-8") as f:
                f.write(hash_password(p1).decode())
            _chmod_safe(ADMIN_HASH_FILE, 0o600)
            print("✅ Mot de passe admin configuré.")
            break

    with open(ADMIN_HASH_FILE, "r", encoding="utf-8") as f:
        saved_hash = f.read().strip()

    attempts = 0
    while True:
        pwd = getpass.getpass("🔒 Entrez mot de passe admin : ")
        if bcrypt.checkpw(pwd.encode(), saved_hash.encode()):
            return pwd
        else:
            print("❌ Mot de passe incorrect.")
            attempts += 1
            time.sleep(min(8, 2 ** min(attempts, 3)))

# -------------------------
# Import
# -------------------------

def import_passwords(fernet, filepath):
    """Importer des mots de passe depuis un fichier JSON externe."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            imported = json.load(f)
    except Exception as e:
        print(f"❌ Erreur lors de l'importation : {e}")
        return

    db = load_db()
    for label, enc_pwd in imported.items():
        if label in db:
            print(f"⚠️  Le label '{label}' existe déjà, import ignoré.")
        else:
            db[label] = enc_pwd
            print(f"✅ Label '{label}' importé avec succès.")

    save_db(db)
    print("📥 Import terminé.")

# -------------------------
# HMAC pour intégrité
# -------------------------
def load_or_create_hmac_key():
    if not os.path.exists(HMAC_KEY_FILE):
        key = secrets.token_bytes(32)
        with open(HMAC_KEY_FILE, "wb") as f:
            f.write(key)
        _chmod_safe(HMAC_KEY_FILE, 0o600)
    else:
        with open(HMAC_KEY_FILE, "rb") as f:
            key = f.read()
    return key

def verify_hmac(passwords: list, hmac_value: str) -> bool:
    """Vérifie l'intégrité HMAC de la liste de mots de passe."""
    if passwords is None or not isinstance(passwords, list):
        raise ValueError("❌ Base de données corrompue ou illisible (JSON non valide).")

    key = load_or_create_hmac_key()
    computed_hmac = hmac.new(
        key,
        json.dumps(passwords, sort_keys=True).encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(computed_hmac, hmac_value):
        raise ValueError("❌ Intégrité compromise : la base de données semble altérée.")

    return True

def save_db_hmac(db, key):
    payload = {
        "passwords": db,
        "hmac": hmac.new(
            key,
            json.dumps(db, sort_keys=True).encode(),
            hashlib.sha256
        ).hexdigest()
    }
    write_json_atomic(DB_FILE, payload)

def load_db():
    """Charge la base des mots de passe avec vérification HMAC."""
    if not os.path.exists(DB_FILE):
        return []

    with open(DB_FILE, "r", encoding="utf-8") as f:
        try:
            payload = json.load(f)
        except Exception as e:
            raise ValueError(f"❌ Fichier DB illisible : {e}")

    passwords = payload.get("passwords")
    hmac_value = payload.get("hmac")

    if passwords is None or hmac_value is None:
        raise ValueError("❌ Fichier DB invalide ou incomplet.")

    verify_hmac(passwords, hmac_value)

    return passwords

def save_db(db):
    save_db_hmac(db, load_or_create_hmac_key())

# -------------------------
# Gestion mots de passe
# -------------------------
def save_password(fernet, label: str, password: str):
    db = load_db()
    if any(entry["label"].lower() == label.lower() for entry in db):
        raise ValueError(f"⚠️ Le label '{label}' existe déjà. Choisissez un autre nom.")
    db.append({"label": label, "password": fernet.encrypt(password.encode()).decode()})
    save_db(db)
    print(f"✅ Mot de passe enregistré pour le label '{label}'")

def import_db(filepath: str, fernet):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            imported = json.load(f)
    except Exception as e:
        raise ValueError(f"❌ Impossible de lire le fichier JSON ({filepath}) : {e}")

    if not isinstance(imported, list):
        raise ValueError("❌ Le fichier importé doit être une liste d'entrées {label, password}")

    db = load_db()
    imported_count = 0
    for entry in imported:
        if "label" not in entry or "password" not in entry:
            print(f"⚠️ Entrée ignorée (format invalide) : {entry}")
            continue
        if any(e['label'].lower() == entry['label'].lower() for e in db):
            print(f"⚠️ Label en doublon ignoré : {entry['label']}")
            continue
        try:
            decrypted = fernet.decrypt(entry["password"].encode()).decode()
            db.append({"label": entry["label"], "password": fernet.encrypt(decrypted.encode()).decode()})
            imported_count += 1
        except Exception:
            print(f"⚠️ Impossible d'importer '{entry['label']}' (chiffrement incompatible).")

    save_db(db)
    print(f"✅ {imported_count} mot(s) de passe importé(s) depuis {filepath}")

def list_passwords(fernet, search=None):
    db = load_db()
    if search:
        db = [e for e in db if search.lower() in e['label'].lower()]
    if not db:
        print("📭 Aucun mot de passe trouvé.")
        return

    # Affichage des labels avec index
    for i, e in enumerate(db, 1):
        print(f"[{i}] {e['label']}")

    try:
        choice = int(input("Sélectionnez un mot de passe à afficher (0 pour annuler) : "))
        if choice == 0:
            return
        if 1 <= choice <= len(db):
            pwd = fernet.decrypt(db[choice-1]["password"].encode()).decode()
            print(f"🔑 Mot de passe pour '{db[choice-1]['label']}' : {pwd}")
            copy(pwd)
        else:
            print("❌ Index invalide")
    except ValueError:
        print("❌ Entrée invalide")

# -------------------------
# Helpers Labels
# -------------------------
def prompt_unique_label(db):
    """Demande un label unique (non vide et non dupliqué)."""
    while True:
        label = input("Entrez un label pour ce mot de passe : ").strip()
        if not label:
            print("❌ Label vide, réessayez.")
            continue
        if any(e['label'].lower() == label.lower() for e in db):
            print(f"❌ Le label '{label}' existe déjà, choisissez-en un autre.")
            continue
        return label

def delete_password(label):
    db = load_db()
    filtered = [e for e in db if e['label'].lower() != label.lower()]
    if len(filtered) == len(db):
        print("❌ Mot de passe non trouvé.")
        return
    save_db(filtered)
    print("✅ Mot de passe supprimé.")

def update_password(fernet, old_label):
    db = load_db()
    matches = [(i, e) for i, e in enumerate(db) if e['label'].lower() == old_label.lower()]
    if not matches:
        print("❌ Mot de passe non trouvé.")
        return
    idx = matches[0][0]

    # Demander si l'utilisateur veut changer le label
    new_label = input(f"Nouveau label (laisser vide pour conserver '{old_label}') : ").strip()
    if new_label:
        if any(e['label'].lower() == new_label.lower() for e in db if e != db[idx]):
            print(f"❌ Un mot de passe avec le label '{new_label}' existe déjà.")
            return
        db[idx]['label'] = new_label

    # Demander le nouveau mot de passe
    new_pwd = getpass.getpass("Nouveau mot de passe : ")
    if new_pwd:
        db[idx]["password"] = fernet.encrypt(new_pwd.encode()).decode()

    save_db(db)
    print("✅ Mot de passe mis à jour.")

def nuke_all():
    for f in (DB_FILE, SALT_FILE, ADMIN_HASH_FILE, META_FILE, HMAC_KEY_FILE):
        if os.path.exists(f):
            os.remove(f)
    print("💣 Toutes les données supprimées.")

# -------------------------
# Générateur
# -------------------------
def generate_password(length=12, exclude_ambiguous=False):
    if exclude_ambiguous:
        chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+"
    else:
        chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(chars) for _ in range(length))

def load_dictionary(path="dictionary.txt"):
    if not os.path.exists(path):
        return ["pomme","chien","voiture","soleil","lune","chat","fromage","table","maison","nuage","livre"]
    with open(path, "r", encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip()]

def generate_dictionary_password(nb_words=4, separator="-", path="dictionary.txt"):
    words = load_dictionary(path)
    return separator.join(secrets.choice(words) for _ in range(nb_words))

def copy(text):
    try:
        import pyperclip
        pyperclip.copy(text)
        print("📋 Le texte a été copié dans le presse-papier")
    except Exception:
        print("⚠️ Impossible de copier dans le presse-papier")

# -------------------------
# Update check
# -------------------------
def check_update():
    try:
        import requests
        r = requests.get(GITHUB_API_URL, timeout=5)
        r.raise_for_status()
        latest = r.json()
        latest_version = latest["tag_name"].lstrip("v")
        if latest_version != __version__:
            print(f"⚡ Nouvelle version {latest_version} disponible !")
            print(f"🔗 {latest['html_url']}")
        else:
            print("✅ Vous êtes à jour.")
    except Exception:
        print("⚠️ Impossible de vérifier les mises à jour.")

# -------------------------
# CLI
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="PassSecure - Gestionnaire de mots de passe")

    # Ajout de l'option interactive
    parser.add_argument("-i", "--interactive", action="store_true", help="Mode interactif")

    parser.add_argument("-l", "--list", action="store_true", help="Lister tous les mots de passe en index (sans mot de passe en clair)")
    parser.add_argument("-r", "--recherche", metavar="LABEL", help="Rechercher un mot de passe")
    parser.add_argument("-s", "--save", nargs=2, metavar=("LABEL", "PWD"), help="Enregistrer un mot de passe")
    parser.add_argument("-u", "--update", metavar="LABEL", help="Mettre à jour un mot de passe")
    parser.add_argument("-del", "--supprimer", metavar="LABEL", help="Supprimer un mot de passe")
    parser.add_argument("-i", "--importer", metavar="FILE", help="Importer mots de passe depuis un fichier JSON")
    parser.add_argument("-n", "--nuke", action="store_true", help="Supprimer toutes les données")
    parser.add_argument("-g", "--generate", action="store_true", help="Générer mot de passe")
    parser.add_argument("-t", "--taille", type=int, default=12, help="Taille du mot de passe aléatoire")
    parser.add_argument("-nbm", "--nb-mots", type=int, default=4, help="Nombre de mots pour mot de passe dictionnaire")
    parser.add_argument("-ea", "--exclure-ambigus", action="store_true", help="Exclure caractères ambigus")
    parser.add_argument("-d", "--dictionnaire", metavar="FILE", default="dictionary.txt", help="Fichier dictionnaire personnalisé")
    parser.add_argument("--check-update", action="store_true", help="Vérifier mise à jour")
    args = parser.parse_args()

    if args.check_update:
        check_update()
        return

    if args.nuke:
        admin_pwd = request_admin_password()
    
        confirm = input("⚠️ Confirmer suppression totale ? (oui) : ")
        if confirm.lower() == "oui":
            nuke_all()
        return

    admin_pwd = request_admin_password()
    salt = load_or_create_salt()
    key = derive_key(admin_pwd, salt)
    fernet = Fernet(key)
    _ensure_permissions()

    if args.generate:
        pwd = generate_password(length=args.taille, exclude_ambiguous=args.exclure_ambigus)
        print(f"🔑 Mot de passe généré : {pwd}")
        copy(pwd)

        if input("Voulez-vous enregistrer ce mot de passe ? (oui/non) : ").strip().lower() == "oui":
            db = load_db()
            label = prompt_unique_label(db)
            save_password(fernet, label, pwd)
            return

    if args.save:
        label, pwd = args.save
        db = load_db()
        if any(e['label'].lower() == label.lower() for e in db):
            print(f"❌ Le label '{label}' existe déjà.")
            return
        save_password(fernet, label, pwd)
        return

    if args.list:
        list_passwords(fernet)
        return

    if args.recherche:
        list_passwords(fernet, search=args.recherche)
        return

    if args.supprimer:
        delete_password(args.supprimer)
        return

    if args.update:
        update_password(fernet, args.update)
        return

    if args.importer:
        try:
            with open(args.importer, "r", encoding="utf-8") as f:
                imported = json.load(f)
            db = load_db()
            for e in imported:
                db.append({"label": e["label"], "password": fernet.encrypt(e["password"].encode()).decode()})
            save_db(db)
            print("✅ Import terminé.")
        except Exception as e:
            print("❌ Erreur import :", e)

    parser.print_help()


if __name__ == "__main__":
    main()
