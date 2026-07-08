#!/usr/bin/env python3
import os
import subprocess
import sys


def print_header(title):
    print(f"\n{'='*60}\n[+] {title}\n{'='*60}")


def check_ssh_config():
    print_header("VÉRIFICATION DE LA CONFIGURATION SSH")
    ssh_config_path = "/etc/ssh/sshd_config"

    if not os.path.exists(ssh_config_path):
        print("[-] Fichier de configuration SSH introuvable.")
        return

    expected_settings = {
        "PermitRootLogin": "no",
        "PasswordAuthentication": "no",
        "PubkeyAuthentication": "yes",
    }

    found_settings = {k: "Non configuré" for k in expected_settings}

    try:
        with open(ssh_config_path, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    key = parts[0]
                    value = parts[1].lower()
                    if key in expected_settings:
                        found_settings[key] = value

        for key, expected in expected_settings.items():
            current = found_settings[key]
            if current == expected:
                print(f"[OK] {key} est correctement configuré sur : {current}")
            else:
                print(f"[CRITIQUE] {key} est sur '{current}' (Attendu : {expected})")

    except PermissionError:
        print("[!] Erreur de permission : Exécutez le script en tant que root.")


def check_cron_jobs():
    print_header("VÉRIFICATION DES TÂCHES PLANIFIÉES (CRON)")
    print("[*] Analyse des répertoires de tâches planifiées...")

    suspicious_found = False

    if os.path.exists("/etc/crontab"):
        with open("/etc/crontab", "r") as f:
            content = f.read()
            if any(cmd in content for cmd in ("curl", "wget", "sh", "bash")):
                print("[ALERTE] Commande suspecte détectée dans /etc/crontab")
                suspicious_found = True

    if not suspicious_found:
        print("[OK] Aucun indicateur de webshell/reverse shell évident dans les crons principaux.")


def check_firewall():
    print_header("VÉRIFICATION DU PARE-FEU (UFW / IPTABLES)")

    try:
        ufw_status = subprocess.check_output(
            ["ufw", "status"], stderr=subprocess.STDOUT
        ).decode().strip()

        if "active" in ufw_status.lower():
            print("[OK] Le pare-feu UFW est ACTIF.")
        else:
            print("[CRITIQUE] UFW est installé mais INACTIF.")

    except FileNotFoundError:
        try:
            iptables_rules = subprocess.check_output(
                ["iptables", "-L", "-n"], stderr=subprocess.STDOUT
            ).decode()

            if "DROP" in iptables_rules or "REJECT" in iptables_rules:
                print("[OK] Des règles iptables restrictives semblent être en place.")
            else:
                print("[ATTENTION] Pare-feu IPTABLES ouvert par défaut (Pas de DROP/REJECT visible).")

        except Exception:
            print("[CRITIQUE] Aucun pare-feu (UFW/IPTABLES) n'a pu être audité.")


def check_critical_permissions():
    print_header("VÉRIFICATION DES PERMISSIONS CRITIQUES")

    sensitive_files = {
        "/etc/shadow": 0o640,
        "/etc/passwd": 0o644,
        "/etc/gshadow": 0o640,
    }

    for path, max_perm in sensitive_files.items():
        if os.path.exists(path):
            current_perm = os.stat(path).st_mode & 0o777

            if current_perm <= max_perm:
                print(f"[OK] {path} a des permissions saines ({oct(current_perm)}).")
            else:
                print(f"[CRITIQUE] {path} a des permissions trop larges : {oct(current_perm)} !")


if __name__ == "__main__":
    if os.getuid() != 0:
        print("[ERREUR] Ce script d'audit doit être exécuté avec les privilèges ROOT (sudo).")
        sys.exit(1)

    print("=== SCRIPT D'AUDIT DE SÉCURITÉ POST-INCIDENT (TECHSUD) ===")
    check_ssh_config()
    check_firewall()
    check_critical_permissions()
    check_cron_jobs()
    print_header("FIN DE L'AUDIT")