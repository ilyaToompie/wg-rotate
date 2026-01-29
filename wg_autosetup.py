#!/usr/bin/env python3

import dataclasses
import ipaddress
import os
import random
import re
import shutil
import string
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple


# -----------------------------
# Common helpers / primitives
# -----------------------------

def run(cmd, check=True, capture=False, env=None):
    if capture:
        return subprocess.run(cmd, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    return subprocess.run(cmd, check=check, env=env)


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def is_root() -> bool:
    return os.geteuid() == 0


def read_os_release() -> dict:
    data = {}
    p = Path("/etc/os-release")
    if not p.exists():
        return data
    for line in p.read_text(errors="ignore").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip().strip('"')
    return data


def systemd_present() -> bool:
    return have("systemctl") and Path("/run/systemd/system").exists()


def openrc_present() -> bool:
    return have("rc-service") and Path("/etc/init.d").exists()


def virt_check():
    # same outcome as bash: refuse openvz/lxc
    virt = None
    if have("virt-what"):
        r = run(["virt-what"], check=False, capture=True)
        virt = (r.stdout or "").strip()
    elif have("systemd-detect-virt"):
        r = run(["systemd-detect-virt"], check=False, capture=True)
        virt = (r.stdout or "").strip()

    if virt == "openvz":
        raise RuntimeError("OpenVZ is not supported")
    if virt == "lxc":
        raise RuntimeError(
            "LXC is not supported by this script. WireGuard may run if host has kernel module + container privileges."
        )


def random_port() -> int:
    return random.randint(49152, 65535)


def random_client_name(prefix="client") -> str:
    # 15 chars max (original constraint). Example: client_k3p9x1
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    name = f"{prefix}_{suffix}"
    return name[:15]


def choose_server_nic() -> str:
    # Try to mimic original: parse default route
    if have("ip"):
        r = run(["ip", "-4", "route", "ls"], check=False, capture=True)
        for line in (r.stdout or "").splitlines():
            if line.startswith("default "):
                # look for "dev <nic>"
                m = re.search(r"\bdev\s+(\S+)", line)
                if m:
                    return m.group(1)
    # fallback
    return "eth0"


def choose_public_ip() -> Optional[str]:
    # Same as bash: pick first global address from `ip addr` (not guaranteed truly public on NAT, but matches original).
    if not have("ip"):
        return None
    r4 = run(["ip", "-4", "addr"], check=False, capture=True)
    for line in (r4.stdout or "").splitlines():
        m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/\d+.*\bscope\s+global\b", line)
        if m:
            return m.group(1)
    r6 = run(["ip", "-6", "addr"], check=False, capture=True)
    for line in (r6.stdout or "").splitlines():
        m = re.search(r"\binet6\s+([0-9a-fA-F:]+)/\d+.*\bscope\s+global\b", line)
        if m:
            return m.group(1)
    return None


def wg_genkeypair() -> Tuple[str, str]:
    if not have("wg"):
        raise RuntimeError("wg not found; cannot generate keys")
    priv = run(["wg", "genkey"], capture=True).stdout.strip()
    pub = run(["wg", "pubkey"], capture=True, env=None, cmd=None)  # placeholder


# -----------------------------
# Distribution detection
# -----------------------------

@dataclasses.dataclass
class OSInfo:
    id: str
    version_id: str


def detect_os() -> OSInfo:
    osr = read_os_release()
    os_id = osr.get("ID", "").lower()
    version_id = osr.get("VERSION_ID", "")

    # map oracle-ish
    if Path("/etc/oracle-release").exists():
        os_id = "oracle"

    # arch/alpine markers
    if Path("/etc/arch-release").exists():
        os_id = "arch"
    if Path("/etc/alpine-release").exists():
        os_id = "alpine"

    if not os_id:
        raise RuntimeError("Unable to detect OS (missing /etc/os-release).")

    return OSInfo(id=os_id, version_id=version_id)


def check_supported_os(info: OSInfo):
    os_id = info.id
    v = info.version_id

    def v_major(x: str) -> int:
        try:
            return int(x.split(".", 1)[0])
        except Exception:
            return 0

    if os_id in ("debian", "raspbian"):
        if v_major(v) < 10:
            raise RuntimeError(f"Debian {v} is not supported. Use Debian 10+.")
    elif os_id == "ubuntu":
        if v_major(v) < 18:
            raise RuntimeError(f"Ubuntu {v} is not supported. Use Ubuntu 18.04+.")
    elif os_id == "fedora":
        if v_major(v) < 32:
            raise RuntimeError(f"Fedora {v} is not supported. Use Fedora 32+.")
    elif os_id in ("centos", "almalinux", "rocky"):
        if v.startswith("7"):
            raise RuntimeError(f"{os_id} {v} is not supported. Use 8+.")
    elif os_id in ("oracle", "arch", "alpine"):
        pass
    else:
        raise RuntimeError(
            "Unsupported OS. Expected Debian/Ubuntu/Fedora/CentOS/AlmaLinux/Rocky/Oracle/Arch/Alpine."
        )


# -----------------------------
# Package management (deps only)
# -----------------------------

def install_dependencies(osinfo: OSInfo):
    """
    Install dependencies only (packages).
    This includes wireguard tools/module packages where applicable,
    plus iptables + resolvconf + qrencode equivalents.
    """
    os_id = osinfo.id
    v = osinfo.version_id

    if os_id in ("ubuntu", "debian", "raspbian"):
        run(["apt-get", "update"])
        # resolvconf may be replaced by openresolv on some distros; keep as per original.
        pkgs = ["wireguard", "iptables", "resolvconf", "qrencode"]
        run(["apt-get", "install", "-y"] + pkgs)

    elif os_id == "fedora":
        # Modern Fedora has wireguard-tools
        pkgs = ["wireguard-tools", "iptables", "qrencode"]
        run(["dnf", "install", "-y"] + pkgs)

    elif os_id in ("centos", "almalinux", "rocky"):
        # best effort: EL8+ expects epel/elrepo for kmod-wireguard; EL9 has wireguard-tools but module often in kernel.
        major = int(v.split(".", 1)[0]) if v else 0
        if major == 8:
            run(["yum", "install", "-y", "epel-release", "elrepo-release"])
            run(["yum", "install", "-y", "kmod-wireguard"], check=False)
            run(["yum", "install", "-y", "qrencode"], check=False)
        run(["yum", "install", "-y", "wireguard-tools", "iptables"], check=False)

    elif os_id == "oracle":
        # Similar to original (EL8)
        run(["dnf", "install", "-y", "oraclelinux-developer-release-el8"])
        run(["dnf", "config-manager", "--disable", "-y", "ol8_developer"], check=False)
        run(["dnf", "config-manager", "--enable", "-y", "ol8_developer_UEKR6"], check=False)
        run(["dnf", "config-manager", "--save", "-y", "--setopt=ol8_developer_UEKR6.includepkgs=wireguard-tools*"])
        run(["dnf", "install", "-y", "wireguard-tools", "qrencode", "iptables"])

    elif os_id == "arch":
        run(["pacman", "-S", "--needed", "--noconfirm", "wireguard-tools", "qrencode"])

    elif os_id == "alpine":
        run(["apk", "update"])
        run(["apk", "add", "wireguard-tools", "iptables", "libqrencode-tools"], check=False)
        # virt-what optional; not required.

    else:
        raise RuntimeError(f"Unsupported OS for dependency install: {os_id}")

    # Validate wg presence after deps install
    if not have("wg"):
        raise RuntimeError("WireGuard installation failed: 'wg' command not found after installing dependencies.")


def uninstall_dependencies(osinfo: OSInfo):
    """
    Uninstall dependencies only (packages).
    WARNING: this removes wireguard-tools/wireguard packages and helpers.
    """
    os_id = osinfo.id

    if os_id in ("ubuntu", "debian", "raspbian"):
        run(["apt-get", "remove", "-y", "wireguard", "wireguard-tools", "qrencode", "resolvconf", "iptables"], check=False)
        run(["apt-get", "autoremove", "-y"], check=False)

    elif os_id == "fedora":
        run(["dnf", "remove", "-y", "--noautoremove", "wireguard-tools", "qrencode", "iptables"], check=False)

    elif os_id in ("centos", "almalinux", "rocky"):
        run(["yum", "remove", "-y", "--noautoremove", "wireguard-tools", "iptables", "qrencode", "kmod-wireguard"], check=False)

    elif os_id == "oracle":
        run(["dnf", "remove", "-y", "--noautoremove", "wireguard-tools", "qrencode", "iptables"], check=False)

    elif os_id == "arch":
        run(["pacman", "-Rs", "--noconfirm", "wireguard-tools", "qrencode"], check=False)

    elif os_id == "alpine":
        run(["apk", "del", "wireguard-tools", "iptables", "libqrencode-tools", "libqrencode"], check=False)

    else:
        raise RuntimeError(f"Unsupported OS for dependency uninstall: {os_id}")


# -----------------------------
# WireGuard setup/resetup
# -----------------------------

@dataclasses.dataclass
class WGConfig:
    server_pub_ip: str
    server_pub_nic: str
    wg_nic: str
    server_ipv4: str
    server_ipv6: str
    server_port: int
    dns1: str
    dns2: str
    allowed_ips: str
    client_name: str
    client_ipv4: str
    client_ipv6: str


def wg_keypair() -> Tuple[str, str]:
    priv = run(["wg", "genkey"], capture=True).stdout.strip()
    pub = run(["bash", "-lc", "echo -n \"$0\" | wg pubkey", priv], capture=True).stdout.strip()
    return priv, pub


def wg_psk() -> str:
    return run(["wg", "genpsk"], capture=True).stdout.strip()


def is_firewalld_running() -> bool:
    # replicate bash test: pgrep firewalld
    r = run(["pgrep", "firewalld"], check=False)
    return r.returncode == 0 and have("firewall-cmd")


def default_addresses() -> Tuple[str, str]:
    # Keep defaults from original (predictable); “random settings” will come from port + keys + client identity.
    return "10.66.66.1", "fd42:42:42::1"


def allocate_client_ip(server_ipv4: str, server_ipv6: str) -> Tuple[str, str]:
    # For /24 server subnet, choose .2-.254. Here we just pick a random available IP without scanning.
    # Since this is a full resetup, we can safely pick a random dot in range.
    base_v4 = ".".join(server_ipv4.split(".")[:3])
    dot = random.randint(2, 254)
    client_v4 = f"{base_v4}.{dot}"

    # IPv6: use same dot as last hextet-ish (simple mimic)
    base_v6 = server_ipv6.split("::", 1)[0]
    client_v6 = f"{base_v6}::{dot}"
    return client_v4, client_v6


def bracket_if_ipv6(ip: str) -> str:
    if ":" in ip and not (ip.startswith("[") and ip.endswith("]")):
        return f"[{ip}]"
    return ip


def stop_existing_wg_services():
    # Stop all wg-quick@*.service (best-effort) and OpenRC wg-quick.* services
    if systemd_present():
        # list units
        r = run(["bash", "-lc", "systemctl list-units --type=service --all | awk '{print $1}'"], capture=True, check=False)
        units = set((r.stdout or "").split())
        for u in sorted(units):
            if u.startswith("wg-quick@") and u.endswith(".service"):
                run(["systemctl", "stop", u], check=False)
                run(["systemctl", "disable", u], check=False)

    if openrc_present():
        # Stop any wg-quick.* services
        initd = Path("/etc/init.d")
        for p in initd.glob("wg-quick.*"):
            name = p.name
            run(["rc-service", name, "stop"], check=False)
            run(["rc-update", "del", name], check=False)


def purge_wireguard_state():
    # Stop services first so PostDown executes.
    stop_existing_wg_services()

    # Remove config + params + sysctl file
    shutil.rmtree("/etc/wireguard", ignore_errors=True)
    try:
        Path("/etc/sysctl.d/wg.conf").unlink()
    except FileNotFoundError:
        pass

    # Reload sysctl (best effort)
    if have("sysctl"):
        run(["sysctl", "--system"], check=False)

    # On Alpine, sysctl is handled by rc-service sysctl (best effort)
    if openrc_present():
        run(["rc-service", "sysctl", "restart"], check=False)


def write_file(path: str, content: str, mode: Optional[int] = None):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    if mode is not None:
        os.chmod(path, mode)


def setup_wireguard_fresh(osinfo: OSInfo) -> WGConfig:
    # Ensure deps + wg exist (non-interactive)
    if not have("wg"):
        install_dependencies(osinfo)

    server_pub_ip = choose_public_ip() or "127.0.0.1"
    server_pub_nic = choose_server_nic()
    wg_nic = "wg0"
    server_ipv4, server_ipv6 = default_addresses()
    port = random_port()
    dns1, dns2 = "1.1.1.1", "1.0.0.1"
    allowed_ips = "0.0.0.0/0,::/0"
    client_name = random_client_name("client")
    client_ipv4, client_ipv6 = allocate_client_ip(server_ipv4, server_ipv6)

    # Generate keys
    server_priv, server_pub = wg_keypair()
    client_priv, client_pub = wg_keypair()
    psk = wg_psk()

    # Save params (for observability)
    params = (
        f"SERVER_PUB_IP={server_pub_ip}\n"
        f"SERVER_PUB_NIC={server_pub_nic}\n"
        f"SERVER_WG_NIC={wg_nic}\n"
        f"SERVER_WG_IPV4={server_ipv4}\n"
        f"SERVER_WG_IPV6={server_ipv6}\n"
        f"SERVER_PORT={port}\n"
        f"SERVER_PRIV_KEY={server_priv}\n"
        f"SERVER_PUB_KEY={server_pub}\n"
        f"CLIENT_DNS_1={dns1}\n"
        f"CLIENT_DNS_2={dns2}\n"
        f"ALLOWED_IPS={allowed_ips}\n"
        f"CLIENT_NAME={client_name}\n"
        f"CLIENT_WG_IPV4={client_ipv4}\n"
        f"CLIENT_WG_IPV6={client_ipv6}\n"
    )
    write_file("/etc/wireguard/params", params, mode=0o600)

    # Build server config
    server_conf_lines = [
        "[Interface]",
        f"Address = {server_ipv4}/24,{server_ipv6}/64",
        f"ListenPort = {port}",
        f"PrivateKey = {server_priv}",
    ]

    if is_firewalld_running():
        fw_ipv4_net = ".".join(server_ipv4.split(".")[:3]) + ".0/24"
        # original script used /24 for v6 rich-rule from a modified string; keep best-effort:
        # use the /64 as source and masquerade. firewalld rich-rule family=ipv6 supports source address prefix.
        fw_ipv6_net = str(ipaddress.IPv6Network(server_ipv6 + "/64", strict=False))

        server_conf_lines += [
            (
                "PostUp = "
                f"firewall-cmd --zone=public --add-interface={wg_nic} && "
                f"firewall-cmd --add-port {port}/udp && "
                f"firewall-cmd --add-rich-rule='rule family=ipv4 source address={fw_ipv4_net} masquerade' && "
                f"firewall-cmd --add-rich-rule='rule family=ipv6 source address={fw_ipv6_net} masquerade'"
            ),
            (
                "PostDown = "
                f"firewall-cmd --zone=public --remove-interface={wg_nic} && "
                f"firewall-cmd --remove-port {port}/udp && "
                f"firewall-cmd --remove-rich-rule='rule family=ipv4 source address={fw_ipv4_net} masquerade' && "
                f"firewall-cmd --remove-rich-rule='rule family=ipv6 source address={fw_ipv6_net} masquerade'"
            ),
        ]
    else:
        server_conf_lines += [
            f"PostUp = iptables -I INPUT -p udp --dport {port} -j ACCEPT",
            f"PostUp = iptables -I FORWARD -i {server_pub_nic} -o {wg_nic} -j ACCEPT",
            f"PostUp = iptables -I FORWARD -i {wg_nic} -j ACCEPT",
            f"PostUp = iptables -t nat -A POSTROUTING -o {server_pub_nic} -j MASQUERADE",
            f"PostUp = ip6tables -I FORWARD -i {wg_nic} -j ACCEPT",
            f"PostUp = ip6tables -t nat -A POSTROUTING -o {server_pub_nic} -j MASQUERADE",
            f"PostDown = iptables -D INPUT -p udp --dport {port} -j ACCEPT",
            f"PostDown = iptables -D FORWARD -i {server_pub_nic} -o {wg_nic} -j ACCEPT",
            f"PostDown = iptables -D FORWARD -i {wg_nic} -j ACCEPT",
            f"PostDown = iptables -t nat -D POSTROUTING -o {server_pub_nic} -j MASQUERADE",
            f"PostDown = ip6tables -D FORWARD -i {wg_nic} -j ACCEPT",
            f"PostDown = ip6tables -t nat -D POSTROUTING -o {server_pub_nic} -j MASQUERADE",
        ]

    # Add peer (client) to server config
    server_conf_lines += [
        "",
        f"### Client {client_name}",
        "[Peer]",
        f"PublicKey = {client_pub}",
        f"PresharedKey = {psk}",
        f"AllowedIPs = {client_ipv4}/32,{client_ipv6}/128",
        "",
    ]

    server_conf_path = f"/etc/wireguard/{wg_nic}.conf"
    write_file(server_conf_path, "\n".join(server_conf_lines), mode=0o600)

    # Enable routing
    write_file(
        "/etc/sysctl.d/wg.conf",
        "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n",
        mode=0o644,
    )
    if have("sysctl"):
        run(["sysctl", "--system"], check=False)

    # Client config file: store in /root by default (no prompts)
    endpoint_ip = bracket_if_ipv6(server_pub_ip)
    endpoint = f"{endpoint_ip}:{port}"
    client_conf_lines = [
        "[Interface]",
        f"PrivateKey = {client_priv}",
        f"Address = {client_ipv4}/32,{client_ipv6}/128",
        f"DNS = {dns1},{dns2}",
        "",
        "[Peer]",
        f"PublicKey = {server_pub}",
        f"PresharedKey = {psk}",
        f"Endpoint = {endpoint}",
        f"AllowedIPs = {allowed_ips}",
        "",
    ]
    client_conf_path = f"/root/{wg_nic}-client-{client_name}.conf"
    write_file(client_conf_path, "\n".join(client_conf_lines), mode=0o600)

    # Bring up interface
    if osinfo.id == "alpine" and openrc_present():
        # Create wg-quick.<nic> symlink and enable service
        # OpenRC name in original: /etc/init.d/wg-quick.<nic>
        base_init = Path("/etc/init.d/wg-quick")
        if base_init.exists():
            target = Path(f"/etc/init.d/wg-quick.{wg_nic}")
            if not target.exists():
                target.symlink_to(base_init)
            run(["rc-update", "add", "sysctl"], check=False)
            run(["rc-service", "sysctl", "start"], check=False)
            run(["rc-service", f"wg-quick.{wg_nic}", "start"], check=False)
            run(["rc-update", "add", f"wg-quick.{wg_nic}"], check=False)
        else:
            # fallback: try wg-quick directly
            run(["wg-quick", "up", wg_nic], check=False)
    else:
        if systemd_present():
            run(["systemctl", "start", f"wg-quick@{wg_nic}"], check=False)
            run(["systemctl", "enable", f"wg-quick@{wg_nic}"], check=False)
        else:
            run(["wg-quick", "up", wg_nic], check=False)

    return WGConfig(
        server_pub_ip=server_pub_ip,
        server_pub_nic=server_pub_nic,
        wg_nic=wg_nic,
        server_ipv4=server_ipv4,
        server_ipv6=server_ipv6,
        server_port=port,
        dns1=dns1,
        dns2=dns2,
        allowed_ips=allowed_ips,
        client_name=client_name,
        client_ipv4=client_ipv4,
        client_ipv6=client_ipv6,
    )


def resetup_wireguard(osinfo: OSInfo) -> WGConfig:
    # If WG exists or params exist, purge everything and recreate with new random settings
    purge_wireguard_state()
    return setup_wireguard_fresh(osinfo)


def wg_running(wg_nic: str, osinfo: OSInfo) -> bool:
    if osinfo.id == "alpine" and openrc_present():
        r = run(["rc-service", f"wg-quick.{wg_nic}", "status"], check=False)
        return r.returncode == 0
    if systemd_present():
        r = run(["systemctl", "is-active", "--quiet", f"wg-quick@{wg_nic}"], check=False)
        return r.returncode == 0
    # fallback: check `wg show`
    r = run(["wg", "show"], check=False)
    return r.returncode == 0


# -----------------------------
# Entry point
# -----------------------------

def main():
    if not is_root():
        print("ERROR: You need to run this script as root.", file=sys.stderr)
        sys.exit(1)

    osinfo = detect_os()
    check_supported_os(osinfo)
    virt_check()

    # Always resetup (per requirement: if run after installation — remove daemons and setup again)
    # If wg not installed, resetup() will install deps and do initial setup.
    try:
        cfg = resetup_wireguard(osinfo)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    ok = wg_running(cfg.wg_nic, osinfo)

    print("WireGuard non-interactive setup complete.")
    print(f"OS: {osinfo.id} {osinfo.version_id}")
    print(f"Interface: {cfg.wg_nic}")
    print(f"Endpoint: {bracket_if_ipv6(cfg.server_pub_ip)}:{cfg.server_port}")
    print(f"Server IPv4/IPv6: {cfg.server_ipv4}/24  {cfg.server_ipv6}/64")
    print(f"Client: {cfg.client_name}")
    print(f"Client config: /root/{cfg.wg_nic}-client-{cfg.client_name}.conf")
    print(f"Service running: {'yes' if ok else 'no'}")
    if not ok:
        print("WARNING: WireGuard does not appear to be running. A reboot may be required (kernel/module updates).")


if __name__ == "__main__":
    main()
