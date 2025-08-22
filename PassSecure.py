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
import requests
import threading
import time

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# -------------------------
# Version & URL de maj
# -------------------------
__version__ = "1.0.0"
GITHUB_API_URL = "https://api.github.com/repos/SeikoSanOf/SecureCore/releases/latest"

# -------------------------
# Dossiers et fichiers
# -------------------------
SECURE_DIR = os.path.expanduser("~/.passsecure")
SALT_FILE = os.path.join(SECURE_DIR, "salt.bin")
ADMIN_HASH_FILE = os.path.join(SECURE_DIR, "admin_hash.txt")
DB_FILE = os.path.join(SECURE_DIR, "passwords.json")
META_FILE = os.path.join(SECURE_DIR, "meta.json")

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
    for f in (SALT_FILE, ADMIN_HASH_FILE, DB_FILE, META_FILE):
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

def derive_key(password, salt):
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
        pwd = getpass.getpass("🔐 Entrez mot de passe admin : ")
        if bcrypt.checkpw(pwd.encode(), saved_hash.encode()):
            return pwd
        else:
            print("❌ Mot de passe incorrect.")
            attempts += 1
            time.sleep(min(8, 2 ** min(attempts, 3)))

# -------------------------
# Génération mots de passe
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

# -------------------------
# Clipboard auto-clear
# -------------------------
def copy_with_clear(text, ttl=20):
    pyperclip.copy(text)
    def clear():
        time.sleep(ttl)
        try:
            if pyperclip.paste() == text:
                pyperclip.copy("")
        except Exception:
            pass
    threading.Thread(target=clear, daemon=True).start()

# -------------------------
# Base de données
# -------------------------
def load_db():
    if not os.path.exists(DB_FILE):
        return []
    with open(DB_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return []

def save_db(db):
    write_json_atomic(DB_FILE, db)

def save_password_entry(fernet, label, pwd):
    db = load_db()
    db.append({"label": label, "password": fernet.encrypt(pwd.encode()).decode()})
    save_db(db)

def list_passwords(fernet, search=None):
    db = load_db()
    if search:
        db = [e for e in db if search.lower() in e['label'].lower()]
    if not db:
        print("📭 Aucun mot de passe trouvé.")
        return
    for e in db:
        try:
            pwd = fernet.decrypt(e["password"].encode()).decode()
        except:
            pwd = "[ERREUR]"
        print(f"{e['label']} : {pwd}")

def delete_password(fernet, label):
    db = load_db()
    filtered = [e for e in db if e['label'].lower() != label.lower()]
    if len(filtered) == len(db):
        print("❌ Mot de passe non trouvé.")
        return
    save_db(filtered)
    print("✅ Mot de passe supprimé.")

def update_password(fernet, label):
    db = load_db()
    matches = [(i,e) for i,e in enumerate(db) if e['label'].lower() == label.lower()]
    if not matches:
        print("❌ Mot de passe non trouvé.")
        return
    idx = matches[0][0]
    new_pwd = getpass.getpass("Nouveau mot de passe : ")
    db[idx]["password"] = fernet.encrypt(new_pwd.encode()).decode()
    save_db(db)
    print("✅ Mot de passe mis à jour.")

def nuke_all():
    for f in (DB_FILE, SALT_FILE, ADMIN_HASH_FILE, META_FILE):
        if os.path.exists(f):
            os.remove(f)
    print("💣 Toutes les données supprimées.")

# -------------------------
# Update check
# -------------------------
def check_update():
    try:
        r = requests.get(GITHUB_API_URL)
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
    parser.add_argument("-l", "--list", action="store_true", help="Lister les mots de passe")
    parser.add_argument("-s", "--save", nargs=2, metavar=("LABEL", "PWD"), help="Enregistrer mot de passe")
    parser.add_argument("-d", "--delete", metavar="LABEL", help="Supprimer mot de passe")
    parser.add_argument("-u", "--update", metavar="LABEL", help="Mettre à jour mot de passe")
    parser.add_argument("-g", "--generate", action="store_true", help="Générer mot de passe aléatoire")
    parser.add_argument("--nb-words", type=int, default=4, help="Nb de mots pour mot de passe dictionnaire")
    parser.add_argument("--check-update", action="store_true", help="Vérifier mise à jour")
    parser.add_argument("--nuke", action="store_true", help="Supprimer toutes les données")
    args = parser.parse_args()

    if args.check_update:
        check_update()
        return

    if args.nuke:
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
        pwd = generate_dictionary_password(nb_words=args.nb_words)
        print(f"🔑 Mot de passe généré : {pwd}")
        copy_with_clear(pwd)
    elif args.save:
        label, pwd = args.save
        save_password_entry(fernet, label, pwd)
        print("✅ Mot de passe sauvegardé.")
    elif args.list:
        list_passwords(fernet)
    elif args.delete:
        delete_password(fernet, args.delete)
    elif args.update:
        update_password(fernet, args.update)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
