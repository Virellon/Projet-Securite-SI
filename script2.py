import subprocess
import re

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()

def check_root_login():
    conf = run("cat /etc/ssh/sshd_config")
    ok = re.search(r"^PermitRootLogin\s+no", conf, re.MULTILINE) is not None
    return "PermitRootLogin no", ok

def check_password_auth():
    conf = run("cat /etc/ssh/sshd_config")
    ok = re.search(r"^PasswordAuthentication\s+no", conf, re.MULTILINE) is not None
    return "PasswordAuthentication no", ok

def check_PubkeyAuthentication(): 
    conf = run("car /etc/ssh/sshd_config")
    ok = re.search(r"PubkeyAuthentification\s+no", conf , re.MULTILINE) is not None
    return "PubkeyAuthentication no", ok

def check_ufw_active():
    status = run("ufw status")
    ok = "Status: active" in status
    return "UFW actif", ok

def check_root_locked():
    shadow = run("sudo grep root /etc/shadow")
    ok = shadow.split(":")[1].startswith("!") or shadow.split(":")[1].startswith("*")
    return "Compte root verrouillé", ok

def check_no_suid_unexpected():
    result = run("find / -perm -4000 -type f 2>/dev/null")
    count = len(result.splitlines())
    return f"Binaires SUID trouvés ({count})", count < 15  # seuil indicatif, à ajuster

def check_unwanted_services():
    # Liste des services jugés non nécessaires sur ce serveur (à adapter selon le contexte)
    unwanted = ["avahi-daemon", "cups", "bluetooth", "rpcbind", "ftp"]
    active = run("systemctl list-units --type=service --state=running --no-legend")
    found = [s for s in unwanted if s in active]
    ok = len(found) == 0
    label = "Aucun service non désiré actif" if ok else f"Services non désirés actifs : {', '.join(found)}"
    return label, ok

def check_fail2ban_active():
    status = run("systemctl is-active fail2ban")
    ok = status == "active"
    return "fail2ban actif", ok

CHECKS = [
    check_root_login,
    check_password_auth,
    check_PubkeyAuthentication,
    check_ufw_active,
    check_root_locked,
    check_no_suid_unexpected,
    check_unwanted_services,
    check_fail2ban_active,
]

def main():
    print("=== AEGIS - Audit de sécurité ===\n")
    results = []
    for check in CHECKS:
        label, ok = check()
        status = "[OK]" if ok else "[FAIL]"
        print(f"{status} {label}")
        results.append(ok)

    total = len(results)
    passed = sum(results)
    print(f"\nScore : {passed}/{total}")

if __name__ == "__main__":
    main()
 