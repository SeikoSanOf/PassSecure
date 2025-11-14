#!/usr/bin/env python3
"""
PassSecure GUI - Interface graphique avec customtkinter
Reprend toutes les fonctionnalités de PassSecure.py
"""

import os
import sys
import json
import base64
import bcrypt
import getpass
import secrets
import string
import pyperclip
import tempfile
import threading
import time
import hmac
import hashlib
import datetime

import customtkinter as ctk
from tkinter import messagebox, filedialog, simpledialog
from PIL import Image, ImageDraw

try:
    import argon2
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# -------------------------
# Configuration
# -------------------------
__version__ = "1.0.1"
GITHUB_API_URL = "https://api.github.com/repos/SeikoSanOf/PassSecure/releases/latest"
SECURE_DIR = os.path.expanduser("~/.passsecure")
SALT_FILE = os.path.join(SECURE_DIR, "salt.bin")
ADMIN_HASH_FILE = os.path.join(SECURE_DIR, "admin_hash.txt")
DB_FILE = os.path.join(SECURE_DIR, "passwords.json")
META_FILE = os.path.join(SECURE_DIR, "meta.json")
HMAC_KEY_FILE = os.path.join(SECURE_DIR, "hmac.key")

# Définir le thème customtkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

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

def request_admin_password_gui(root=None):
    """Version GUI de request_admin_password"""
    os.makedirs(SECURE_DIR, exist_ok=True)
    _chmod_safe(SECURE_DIR, 0o700)

    if not os.path.exists(ADMIN_HASH_FILE):
        # Créer un nouveau mot de passe
        while True:
            p1 = simpledialog.askstring("Admin", "Créez un mot de passe admin :", show='*')
            if p1 is None:
                return None
            p2 = simpledialog.askstring("Admin", "Confirmez le mot de passe :", show='*')
            if p2 is None:
                return None
            if p1 != p2:
                messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas.")
                continue
            if not p1.strip():
                messagebox.showerror("Erreur", "Le mot de passe ne peut pas être vide.")
                continue
            with open(ADMIN_HASH_FILE, "w", encoding="utf-8") as f:
                f.write(hash_password(p1).decode())
            _chmod_safe(ADMIN_HASH_FILE, 0o600)
            messagebox.showinfo("Succès", "Mot de passe admin configuré.")
            return p1

    # Vérifier le mot de passe existant
    with open(ADMIN_HASH_FILE, "r", encoding="utf-8") as f:
        saved_hash = f.read().strip()

    attempts = 0
    while True:
        pwd = simpledialog.askstring("Authentification", "Entrez le mot de passe admin :", show='*')
        if pwd is None:
            return None
        if bcrypt.checkpw(pwd.encode(), saved_hash.encode()):
            return pwd
        else:
            messagebox.showerror("Erreur", "Mot de passe incorrect.")
            attempts += 1
            if attempts >= 3:
                messagebox.showerror("Erreur", "Trop de tentatives. Fermeture.")
                return None

# -------------------------
# HMAC et DB
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
    if passwords is None or not isinstance(passwords, list):
        raise ValueError("Base de données corrompue ou illisible.")
    
    key = load_or_create_hmac_key()
    computed_hmac = hmac.new(
        key,
        json.dumps(passwords, sort_keys=True).encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(computed_hmac, hmac_value):
        raise ValueError("Intégrité compromise : la base de données semble altérée.")
    
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
    if not os.path.exists(DB_FILE):
        return []

    with open(DB_FILE, "r", encoding="utf-8") as f:
        try:
            payload = json.load(f)
        except Exception as e:
            raise ValueError(f"Fichier DB illisible : {e}")

    passwords = payload.get("passwords")
    hmac_value = payload.get("hmac")

    if passwords is None or hmac_value is None:
        raise ValueError("Fichier DB invalide ou incomplet.")

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
        raise ValueError(f"Le label '{label}' existe déjà.")
    db.append({"label": label, "password": fernet.encrypt(password.encode()).decode()})
    save_db(db)

def get_password(fernet, label: str):
    db = load_db()
    for entry in db:
        if entry["label"].lower() == label.lower():
            return fernet.decrypt(entry["password"].encode()).decode()
    return None

def delete_password(label):
    db = load_db()
    filtered = [e for e in db if e['label'].lower() != label.lower()]
    if len(filtered) == len(db):
        raise ValueError("Mot de passe non trouvé.")
    save_db(filtered)

def update_password(fernet, old_label, new_label=None, new_pwd=None):
    db = load_db()
    matches = [(i, e) for i, e in enumerate(db) if e['label'].lower() == old_label.lower()]
    if not matches:
        raise ValueError("Mot de passe non trouvé.")
    
    idx = matches[0][0]
    if new_label:
        db[idx]['label'] = new_label
    if new_pwd:
        db[idx]["password"] = fernet.encrypt(new_pwd.encode()).decode()
    
    save_db(db)

def nuke_all():
    for f in (DB_FILE, SALT_FILE, ADMIN_HASH_FILE, META_FILE, HMAC_KEY_FILE):
        if os.path.exists(f):
            os.remove(f)

# -------------------------
# Générateur
# -------------------------
def generate_password(length=12, exclude_ambiguous=False):
    if exclude_ambiguous:
        chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+"
    else:
        chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(chars) for _ in range(length))

def copy_to_clipboard(text):
    try:
        pyperclip.copy(text)
        return True
    except Exception:
        return False

# -------------------------
# Password strength checker
# -------------------------
def check_password_strength(password):
    """Évalue la force d'un mot de passe"""
    score = 0
    feedback = []
    
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Au moins 8 caractères")
    
    if len(password) >= 12:
        score += 1
    
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Ajoutez des majuscules")
    
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Ajoutez des minuscules")
    
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Ajoutez des chiffres")
    
    if any(c in "!@#$%^&*()-_=+" for c in password):
        score += 1
    else:
        feedback.append("Ajoutez des caractères spéciaux")
    
    # Déterminer le niveau de force
    if score <= 2:
        strength = "Faible"
        color = "#ff4444"
    elif score <= 4:
        strength = "Moyen"
        color = "#ffaa00"
    else:
        strength = "Fort"
        color = "#00cc00"
    
    return strength, color, feedback

# -------------------------
# Action logger
# -------------------------
class ActionLogger:
    """Enregistre les actions pour l'audit"""
    def __init__(self, log_file=None):
        self.log_file = log_file or os.path.join(SECURE_DIR, "audit.log")
        os.makedirs(SECURE_DIR, exist_ok=True)
    
    def log_action(self, action, details=""):
        """Enregistre une action avec timestamp"""
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] {action} {details}\n"
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(log_entry)
            _chmod_safe(self.log_file, 0o600)
        except Exception:
            pass
    
    def get_recent_actions(self, limit=20):
        """Récupère les actions récentes"""
        try:
            if not os.path.exists(self.log_file):
                return []
            with open(self.log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            return lines[-limit:]
        except Exception:
            return []

# -------------------------
# Update check
# -------------------------
def check_update():
    """Vérifier si une nouvelle version est disponible"""
    try:
        import requests
        r = requests.get(GITHUB_API_URL, timeout=5)
        r.raise_for_status()
        latest = r.json()
        latest_version = latest["tag_name"].lstrip("v")
        if latest_version != __version__:
            return {
                "update_available": True,
                "version": latest_version,
                "url": latest['html_url'],
                "message": f"Nouvelle version {latest_version} disponible !"
            }
        else:
            return {
                "update_available": False,
                "version": __version__,
                "message": "Vous êtes à jour."
            }
    except Exception as e:
        return {
            "update_available": None,
            "error": str(e),
            "message": "Impossible de vérifier les mises à jour."
        }

# -------------------------
# GUI Application
# -------------------------
class PassSecureGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("PassSecure - Gestionnaire de mots de passe")
        self.geometry("900x700")
        self.resizable(True, True)
        
        # Variables
        self.fernet = None
        self.is_authenticated = False
        self.action_logger = ActionLogger()
        
        # Configuration couleurs
        self.main_color = "#1a1a1a"
        self.accent_color = "#0066cc"
        
        # Écran d'authentification
        self.show_auth_screen()
    
    def show_auth_screen(self):
        """Écran d'authentification"""
        self.clear_widgets()
        
        main_frame = ctk.CTkFrame(self, fg_color=self.main_color)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        title = ctk.CTkLabel(main_frame, text="🔒 PassSecure", font=("Arial", 32, "bold"))
        title.pack(pady=20)
        
        subtitle = ctk.CTkLabel(main_frame, text="Gestionnaire de mots de passe sécurisé", font=("Arial", 14))
        subtitle.pack(pady=10)
        
        # Frame d'authentification
        auth_frame = ctk.CTkFrame(main_frame, fg_color="#2a2a2a", corner_radius=10)
        auth_frame.pack(pady=40, padx=20, fill="both", expand=True, ipady=20)
        
        pwd_label = ctk.CTkLabel(auth_frame, text="Mot de passe admin :", font=("Arial", 12))
        pwd_label.pack(pady=10)
        
        pwd_entry = ctk.CTkEntry(auth_frame, placeholder_text="Entrez le mot de passe", show="*", width=300, height=40)
        pwd_entry.pack(pady=10)
        
        def authenticate():
            pwd = pwd_entry.get()
            if not pwd:
                messagebox.showerror("Erreur", "Veuillez entrer un mot de passe.")
                return
            
            try:
                os.makedirs(SECURE_DIR, exist_ok=True)
                _chmod_safe(SECURE_DIR, 0o700)
                
                if not os.path.exists(ADMIN_HASH_FILE):
                    # Créer le mot de passe admin
                    with open(ADMIN_HASH_FILE, "w", encoding="utf-8") as f:
                        f.write(hash_password(pwd).decode())
                    _chmod_safe(ADMIN_HASH_FILE, 0o600)
                    messagebox.showinfo("Succès", "Mot de passe admin créé.")
                
                with open(ADMIN_HASH_FILE, "r", encoding="utf-8") as f:
                    saved_hash = f.read().strip()
                
                if bcrypt.checkpw(pwd.encode(), saved_hash.encode()):
                    salt = load_or_create_salt()
                    key = derive_key(pwd, salt)
                    self.fernet = Fernet(key)
                    self.is_authenticated = True
                    _ensure_permissions()
                    self.show_main_screen()
                else:
                    messagebox.showerror("Erreur", "Mot de passe incorrect.")
                    pwd_entry.delete(0, "end")
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur d'authentification : {e}")
        
        auth_button = ctk.CTkButton(auth_frame, text="Se connecter", command=authenticate, height=40, font=("Arial", 12, "bold"))
        auth_button.pack(pady=20)
    
    def show_main_screen(self):
        """Écran principal après authentification"""
        self.clear_widgets()
        
        # Header
        header = ctk.CTkFrame(self, fg_color=self.accent_color, height=60)
        header.pack(fill="x", padx=0, pady=0)
        header.pack_propagate(False)
        
        header_content = ctk.CTkFrame(header, fg_color="transparent")
        header_content.pack(fill="both", expand=True, padx=15, pady=10)
        
        title = ctk.CTkLabel(header_content, text="🔐 PassSecure - Tableau de bord", font=("Arial", 18, "bold"), text_color="white")
        title.pack(side="left", anchor="w")
        
        version_label = ctk.CTkLabel(header_content, text=f"v{__version__}", font=("Arial", 10), text_color="#cccccc")
        version_label.pack(side="right", anchor="e")
        
        # Contenu principal
        main_frame = ctk.CTkFrame(self)
        main_frame.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Boutons d'action (en haut)
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(fill="x", pady=(0, 15))
        
        ctk.CTkButton(button_frame, text="➕ Ajouter", command=self.add_password, height=40).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="🔍 Lister", command=self.list_passwords, height=40).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="🎲 Générer", command=self.generate_pwd, height=40).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="⚙️ Paramètres", command=self.show_settings, height=40).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="🚪 Déconnexion", command=self.logout, height=40, fg_color="#cc0000").pack(side="right", padx=5)
        
        # Zone d'affichage
        self.display_frame = ctk.CTkFrame(main_frame, fg_color="#2a2a2a", corner_radius=10)
        self.display_frame.pack(fill="both", expand=True)
        
        welcome_label = ctk.CTkLabel(self.display_frame, text="Bienvenue dans PassSecure !\n\nSélectionnez une action pour commencer.", 
                                     font=("Arial", 14), text_color="#888888")
        welcome_label.pack(pady=40)
    
    def clear_widgets(self):
        """Efface tous les widgets"""
        for widget in self.winfo_children():
            widget.destroy()
    
    def refresh_display(self, content_frame=None):
        """Rafraîchit la zone d'affichage"""
        # Efface tous les widgets du display_frame
        for widget in self.display_frame.winfo_children():
            widget.destroy()
        
        # Ajoute le nouveau contenu s'il existe
        if content_frame:
            # Important : définir le parent correctement
            content_frame.pack(fill="both", expand=True, padx=10, pady=10)
    
    def add_password(self):
        """Ajouter un mot de passe"""
        dialog_window = ctk.CTkToplevel(self)
        dialog_window.title("Ajouter un mot de passe")
        dialog_window.geometry("400x300")
        
        ctk.CTkLabel(dialog_window, text="Label :", font=("Arial", 12)).pack(pady=5)
        label_entry = ctk.CTkEntry(dialog_window, placeholder_text="Ex: Gmail", width=300, height=35)
        label_entry.pack(pady=5)
        
        ctk.CTkLabel(dialog_window, text="Mot de passe :", font=("Arial", 12)).pack(pady=5)
        pwd_entry = ctk.CTkEntry(dialog_window, placeholder_text="Entrez le mot de passe", show="*", width=300, height=35)
        pwd_entry.pack(pady=5)
        
        def save():
            label = label_entry.get().strip()
            pwd = pwd_entry.get()
            
            if not label or not pwd:
                messagebox.showerror("Erreur", "Veuillez remplir tous les champs.")
                return
            
            try:
                save_password(self.fernet, label, pwd)
                messagebox.showinfo("Succès", f"Mot de passe '{label}' enregistré.")
                dialog_window.destroy()
            except Exception as e:
                messagebox.showerror("Erreur", str(e))
        
        ctk.CTkButton(dialog_window, text="Enregistrer", command=save, height=40).pack(pady=20)
    
    def list_passwords(self):
        """Lister tous les mots de passe avec recherche"""
        try:
            db = load_db()
            
            # Efface le contenu précédent
            for widget in self.display_frame.winfo_children():
                widget.destroy()
            
            if not db:
                label = ctk.CTkLabel(self.display_frame, text="Aucun mot de passe enregistré.", font=("Arial", 14), text_color="#888888")
                label.pack(pady=20)
                return
            
            # Frame avec recherche
            search_frame = ctk.CTkFrame(self.display_frame, fg_color="transparent")
            search_frame.pack(fill="x", padx=10, pady=10)
            
            ctk.CTkLabel(search_frame, text="🔍 Rechercher :", font=("Arial", 11)).pack(side="left", padx=5)
            search_var = ctk.StringVar()
            search_entry = ctk.CTkEntry(search_frame, textvariable=search_var, placeholder_text="Tapez pour filtrer...", width=200, height=35)
            search_entry.pack(side="left", padx=5)
            
            # Scrollable frame pour la liste
            scrollable = ctk.CTkScrollableFrame(self.display_frame, fg_color="transparent")
            scrollable.pack(fill="both", expand=True, padx=10, pady=10)
            
            # Fonction pour mettre à jour la liste selon la recherche
            def update_list(*args):
                for widget in scrollable.winfo_children():
                    widget.destroy()
                
                search_text = search_var.get().lower()
                filtered_db = [e for e in db if search_text in e['label'].lower()]
                
                if not filtered_db:
                    label = ctk.CTkLabel(scrollable, text="Aucun résultat trouvé.", font=("Arial", 12), text_color="#888888")
                    label.pack(pady=20)
                    return
                
                for entry in filtered_db:
                    item_frame = ctk.CTkFrame(scrollable, fg_color="#1a1a1a", corner_radius=8)
                    item_frame.pack(fill="x", pady=8, padx=5)
                    
                    info_frame = ctk.CTkFrame(item_frame, fg_color="transparent")
                    info_frame.pack(fill="x", padx=10, pady=10)
                    
                    label = ctk.CTkLabel(info_frame, text=entry["label"], font=("Arial", 12, "bold"))
                    label.pack(side="left", anchor="w")
                    
                    def copy_pwd(e=entry):
                        try:
                            pwd = self.fernet.decrypt(e["password"].encode()).decode()
                            if copy_to_clipboard(pwd):
                                self.action_logger.log_action(f"COPY_PASSWORD", f"Label: {e['label']}")
                                messagebox.showinfo("Succès", f"Mot de passe de '{e['label']}' copié !")
                        except Exception as ex:
                            messagebox.showerror("Erreur", str(ex))
                    
                    def edit_pwd(e=entry):
                        self.edit_password(e["label"])
                    
                    def delete_pwd(e=entry):
                        if messagebox.askyesno("Confirmation", f"Supprimer '{e['label']}' ?"):
                            try:
                                delete_password(e["label"])
                                self.action_logger.log_action(f"DELETE_PASSWORD", f"Label: {e['label']}")
                                messagebox.showinfo("Succès", "Mot de passe supprimé.")
                                self.list_passwords()
                            except Exception as ex:
                                messagebox.showerror("Erreur", str(ex))
                    
                    ctk.CTkButton(info_frame, text="📋 Copier", command=copy_pwd, width=100, height=30, font=("Arial", 10)).pack(side="right", padx=5)
                    ctk.CTkButton(info_frame, text="✏️ Éditer", command=edit_pwd, width=100, height=30, font=("Arial", 10)).pack(side="right", padx=5)
                    ctk.CTkButton(info_frame, text="🗑️ Supprimer", command=delete_pwd, width=100, height=30, font=("Arial", 10), fg_color="#cc0000").pack(side="right", padx=5)
            
            # Bind la recherche
            search_var.trace("w", update_list)
            # Initialiser la liste
            update_list()
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la lecture : {e}")
    
    def edit_password(self, label):
        """Éditer un mot de passe"""
        dialog_window = ctk.CTkToplevel(self)
        dialog_window.title(f"Éditer - {label}")
        dialog_window.geometry("400x350")
        
        ctk.CTkLabel(dialog_window, text="Nouveau label :", font=("Arial", 12)).pack(pady=5)
        label_entry = ctk.CTkEntry(dialog_window, placeholder_text=label, width=300, height=35)
        label_entry.pack(pady=5)
        
        ctk.CTkLabel(dialog_window, text="Nouveau mot de passe :", font=("Arial", 12)).pack(pady=5)
        pwd_entry = ctk.CTkEntry(dialog_window, placeholder_text="Laissez vide pour ne pas modifier", show="*", width=300, height=35)
        pwd_entry.pack(pady=5)
        
        def save():
            new_label = label_entry.get().strip() or label
            new_pwd = pwd_entry.get()
            
            try:
                update_password(self.fernet, label, new_label=new_label if new_label != label else None, new_pwd=new_pwd if new_pwd else None)
                messagebox.showinfo("Succès", "Mot de passe mis à jour.")
                dialog_window.destroy()
                self.list_passwords()
            except Exception as e:
                messagebox.showerror("Erreur", str(e))
        
        ctk.CTkButton(dialog_window, text="Mettre à jour", command=save, height=40).pack(pady=20)
    
    def generate_pwd(self):
        """Générer un mot de passe avec indicateur de force"""
        dialog_window = ctk.CTkToplevel(self)
        dialog_window.title("Générer un mot de passe")
        dialog_window.geometry("500x500")
        
        ctk.CTkLabel(dialog_window, text="Taille du mot de passe :", font=("Arial", 12)).pack(pady=10)
        length_label = ctk.CTkLabel(dialog_window, text="Taille : 12", font=("Arial", 11))
        length_label.pack(pady=5)
        
        length_value = {"val": 12}
        
        def update_length(value):
            length_value["val"] = int(float(value))
            length_label.configure(text=f"Taille : {length_value['val']}")
            update_strength()
        
        slider = ctk.CTkSlider(dialog_window, from_=8, to=32, command=update_length, width=300, height=30)
        slider.pack(pady=10)
        slider.set(12)
        
        exclude_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(dialog_window, text="Exclure caractères ambigus", variable=exclude_var, command=lambda: update_strength()).pack(pady=10)
        
        ctk.CTkLabel(dialog_window, text="Mot de passe généré :", font=("Arial", 12)).pack(pady=10)
        pwd_display = ctk.CTkEntry(dialog_window, state="disabled", width=300, height=40, font=("Arial", 12))
        pwd_display.pack(pady=5)
        
        # Indicateur de force
        ctk.CTkLabel(dialog_window, text="Force du mot de passe :", font=("Arial", 11)).pack(pady=10)
        strength_frame = ctk.CTkFrame(dialog_window, fg_color="transparent")
        strength_frame.pack(pady=5)
        
        strength_label = ctk.CTkLabel(strength_frame, text="Fort", font=("Arial", 11, "bold"), text_color="#00cc00")
        strength_label.pack(side="left", padx=10)
        
        feedback_label = ctk.CTkLabel(dialog_window, text="", font=("Arial", 9), text_color="#cccccc")
        feedback_label.pack(pady=5)
        
        def generate():
            pwd = generate_password(length=length_value["val"], exclude_ambiguous=exclude_var.get())
            pwd_display.configure(state="normal")
            pwd_display.delete(0, "end")
            pwd_display.insert(0, pwd)
            pwd_display.configure(state="disabled")
            update_strength()
        
        def update_strength():
            pwd_display.configure(state="normal")
            pwd = pwd_display.get()
            pwd_display.configure(state="disabled")
            
            if pwd:
                strength, color, feedback = check_password_strength(pwd)
                strength_label.configure(text=strength, text_color=color)
                feedback_text = "• " + "\n• ".join(feedback) if feedback else "Mot de passe excellent !"
                feedback_label.configure(text=feedback_text)
        
        def copy_gen():
            pwd_display.configure(state="normal")
            pwd = pwd_display.get()
            pwd_display.configure(state="disabled")
            if pwd:
                copy_to_clipboard(pwd)
                self.action_logger.log_action("GENERATE_PASSWORD_COPY", f"Length: {length_value['val']}")
                messagebox.showinfo("Succès", "Mot de passe copié !")
        
        def save_gen():
            pwd_display.configure(state="normal")
            pwd = pwd_display.get()
            pwd_display.configure(state="disabled")
            if not pwd:
                messagebox.showerror("Erreur", "Générez d'abord un mot de passe.")
                return
            
            label = simpledialog.askstring("Label", "Entrez le label pour ce mot de passe :")
            if label:
                try:
                    save_password(self.fernet, label, pwd)
                    self.action_logger.log_action("SAVE_PASSWORD", f"Label: {label}")
                    messagebox.showinfo("Succès", f"Mot de passe '{label}' enregistré.")
                    dialog_window.destroy()
                except Exception as e:
                    messagebox.showerror("Erreur", str(e))
        
        # Initialiser la longueur et générer
        generate()
        
        button_frame = ctk.CTkFrame(dialog_window, fg_color="transparent")
        button_frame.pack(pady=20)
        
        ctk.CTkButton(button_frame, text="🎲 Générer", command=generate).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="📋 Copier", command=copy_gen).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="💾 Enregistrer", command=save_gen).pack(side="left", padx=5)
    
    def show_settings(self):
        """Afficher les paramètres"""
        # Efface le contenu précédent
        for widget in self.display_frame.winfo_children():
            widget.destroy()
        
        title = ctk.CTkLabel(self.display_frame, text="⚙️ Paramètres", font=("Arial", 18, "bold"))
        title.pack(pady=20)
        
        settings_frame = ctk.CTkFrame(self.display_frame, fg_color="#2a2a2a", corner_radius=10)
        settings_frame.pack(padx=20, pady=20, fill="x")
        
        def export_db():
            filepath = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
            if filepath:
                try:
                    db = load_db()
                    with open(filepath, "w", encoding="utf-8") as f:
                        json.dump(db, f, indent=2)
                    self.action_logger.log_action("EXPORT_DATABASE", f"Path: {filepath}")
                    messagebox.showinfo("Succès", f"Base de données exportée vers {filepath}")
                except Exception as e:
                    messagebox.showerror("Erreur", str(e))
        
        def import_db_func():
            filepath = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
            if filepath:
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        imported = json.load(f)
                    
                    db = load_db()
                    for entry in imported:
                        if not any(e['label'].lower() == entry['label'].lower() for e in db):
                            db.append(entry)
                    
                    save_db(db)
                    self.action_logger.log_action("IMPORT_DATABASE", f"Path: {filepath}")
                    messagebox.showinfo("Succès", "Base de données importée.")
                except Exception as e:
                    messagebox.showerror("Erreur", str(e))
        
        def nuke_db():
            if messagebox.askyesno("⚠️ Attention", "Êtes-vous sûr de vouloir supprimer tous les données ?"):
                try:
                    nuke_all()
                    self.action_logger.log_action("NUKE_DATABASE", "All data deleted")
                    messagebox.showinfo("Succès", "Toutes les données ont été supprimées.")
                    self.logout()
                except Exception as e:
                    messagebox.showerror("Erreur", str(e))
        
        def change_master_password():
            """Changer le mot de passe admin"""
            old_pwd = simpledialog.askstring("Changement de mot de passe", "Entrez l'ancien mot de passe admin :", show='*')
            if old_pwd is None:
                return
            
            try:
                with open(ADMIN_HASH_FILE, "r", encoding="utf-8") as f:
                    saved_hash = f.read().strip()
                
                if not bcrypt.checkpw(old_pwd.encode(), saved_hash.encode()):
                    messagebox.showerror("Erreur", "Ancien mot de passe incorrect.")
                    return
                
                new_pwd1 = simpledialog.askstring("Changement de mot de passe", "Entrez le nouveau mot de passe :", show='*')
                if new_pwd1 is None:
                    return
                
                new_pwd2 = simpledialog.askstring("Changement de mot de passe", "Confirmez le nouveau mot de passe :", show='*')
                if new_pwd2 is None:
                    return
                
                if new_pwd1 != new_pwd2:
                    messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas.")
                    return
                
                with open(ADMIN_HASH_FILE, "w", encoding="utf-8") as f:
                    f.write(hash_password(new_pwd1).decode())
                _chmod_safe(ADMIN_HASH_FILE, 0o600)
                
                self.action_logger.log_action("CHANGE_MASTER_PASSWORD", "Success")
                messagebox.showinfo("Succès", "Mot de passe admin changé avec succès !")
            except Exception as e:
                messagebox.showerror("Erreur", str(e))
        
        def view_audit_log():
            """Afficher l'historique des actions"""
            actions = self.action_logger.get_recent_actions(50)
            
            log_window = ctk.CTkToplevel(self)
            log_window.title("Historique des actions")
            log_window.geometry("600x400")
            
            text_frame = ctk.CTkScrollableFrame(log_window, fg_color="transparent")
            text_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            if not actions:
                label = ctk.CTkLabel(text_frame, text="Aucune action enregistrée.", font=("Arial", 12))
                label.pack(pady=20)
            else:
                for action in reversed(actions):
                    label = ctk.CTkLabel(text_frame, text=action.strip(), font=("Courier", 9), text_color="#cccccc", justify="left")
                    label.pack(fill="x", padx=10, pady=2, anchor="w")
        
        def check_updates():
            result = check_update()
            if result["update_available"]:
                msg = f"{result['message']}\n\nCliquez OK pour ouvrir la page de téléchargement."
                if messagebox.showinfo("Mise à jour", msg):
                    import webbrowser
                    webbrowser.open(result["url"])
            elif result["update_available"] is None:
                messagebox.showwarning("Vérification", result["message"])
            else:
                messagebox.showinfo("Vérification", result["message"])
        
        ctk.CTkButton(settings_frame, text="📤 Exporter la base", command=export_db, height=40, width=300).pack(pady=10)
        ctk.CTkButton(settings_frame, text="📥 Importer la base", command=import_db_func, height=40, width=300).pack(pady=10)
        ctk.CTkButton(settings_frame, text="🔑 Changer le mot de passe admin", command=change_master_password, height=40, width=300).pack(pady=10)
        ctk.CTkButton(settings_frame, text="📋 Historique des actions", command=view_audit_log, height=40, width=300).pack(pady=10)
        ctk.CTkButton(settings_frame, text="⚡ Vérifier les mises à jour", command=check_updates, height=40, width=300).pack(pady=10)
        ctk.CTkButton(settings_frame, text="💣 Supprimer toutes les données", command=nuke_db, height=40, width=300, fg_color="#cc0000").pack(pady=10)
    
    def logout(self):
        """Se déconnecter"""
        self.fernet = None
        self.is_authenticated = False
        self.show_auth_screen()

# -------------------------
# Main
# -------------------------
def main():
    app = PassSecureGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
