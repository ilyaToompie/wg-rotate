#!/usr/bin/env python3

import asyncio
import os
import re
import secrets
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

from dotenv import load_dotenv
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.error import BadRequest, Forbidden
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
)

# Load .env first
load_dotenv()

WG_NIC = "wg0"
WG_DIR = Path("/etc/wireguard")
OUT_DIR = Path("/root")

# Configure in .env (recommended):
# RESETUP_SCRIPT=/root/wg_autosetup.py
RESETUP_SCRIPT = os.environ.get("RESETUP_SCRIPT", "./wg_autosetup.py")

regen_lock = asyncio.Lock()


def sh(cmd: List[str], check=True, capture=True) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def load_admins() -> set[int]:
    raw = os.environ.get("ADMIN_IDS", "")
    if not raw:
        raise RuntimeError("ADMIN_IDS not set in .env")
    return {int(x.strip()) for x in raw.split(",") if x.strip().isdigit()}


ADMINS = load_admins()


def must_root():
    if os.geteuid() != 0:
        raise RuntimeError("Bot must run as root (wg/iptables/systemd). Run: sudo -E python3 wg_bot.py")


def is_admin(user_id: int) -> bool:
    return user_id in ADMINS


def sanitize_client_name(name: str) -> str:
    name = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
    return name[:15] if len(name) > 15 else name


@dataclass
class ServerParams:
    server_pub_ip: str
    server_port: int
    server_pub_key: str
    client_dns_1: str
    client_dns_2: str
    allowed_ips: str
    server_wg_ipv4: str
    server_wg_ipv6: str


def parse_params_file(path: Path) -> ServerParams:
    data: Dict[str, str] = {}
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        k, v = line.split("=", 1)
        data[k.strip()] = v.strip()

    required = [
        "SERVER_PUB_IP",
        "SERVER_PORT",
        "SERVER_PUB_KEY",
        "CLIENT_DNS_1",
        "CLIENT_DNS_2",
        "ALLOWED_IPS",
        "SERVER_WG_IPV4",
        "SERVER_WG_IPV6",
    ]
    missing = [k for k in required if k not in data]
    if missing:
        raise RuntimeError(f"Missing keys in {path}: {missing}")

    return ServerParams(
        server_pub_ip=data["SERVER_PUB_IP"],
        server_port=int(data["SERVER_PORT"]),
        server_pub_key=data["SERVER_PUB_KEY"],
        client_dns_1=data["CLIENT_DNS_1"],
        client_dns_2=data["CLIENT_DNS_2"],
        allowed_ips=data["ALLOWED_IPS"],
        server_wg_ipv4=data["SERVER_WG_IPV4"],
        server_wg_ipv6=data["SERVER_WG_IPV6"],
    )


def bracket_if_ipv6(ip: str) -> str:
    if ":" in ip and not (ip.startswith("[") and ip.endswith("]")):
        return f"[{ip}]"
    return ip


def wg_keypair() -> Tuple[str, str]:
    priv = sh(["wg", "genkey"]).stdout.strip()
    pub = sh(["bash", "-lc", f"echo -n '{priv}' | wg pubkey"]).stdout.strip()
    return priv, pub


def wg_psk() -> str:
    return sh(["wg", "genpsk"]).stdout.strip()


def next_client_ipv4(server_ipv4: str, used: set) -> str:
    base = ".".join(server_ipv4.split(".")[:3])
    for _ in range(1000):
        dot = secrets.randbelow(253) + 2  # 2..254
        cand = f"{base}.{dot}"
        if cand not in used:
            used.add(cand)
            return cand
    raise RuntimeError("Unable to allocate IPv4 client address")


def client_ipv6_from(server_ipv6: str, last: int) -> str:
    base = server_ipv6.split("::", 1)[0]
    return f"{base}::{last}"


def add_peer_to_server_conf(server_conf: Path, client_name: str, client_pub: str, psk: str, client_v4: str, client_v6: str):
    block = (
        f"\n### Client {client_name}\n"
        f"[Peer]\n"
        f"PublicKey = {client_pub}\n"
        f"PresharedKey = {psk}\n"
        f"AllowedIPs = {client_v4}/32, {client_v6}/128\n"
    )
    with server_conf.open("a", encoding="utf-8") as f:
        f.write(block + "\n")


def sync_wg_conf(wg_nic: str):
    sh(["bash", "-lc", f"wg syncconf {wg_nic} <(wg-quick strip {wg_nic})"], check=True)


def build_client_conf_text(params: ServerParams, client_priv: str, client_v4: str, client_v6: str, psk: str) -> str:
    endpoint = f"{bracket_if_ipv6(params.server_pub_ip)}:{params.server_port}"
    allowed_ips = params.allowed_ips.replace(",", ", ")
    return (
        "[Interface]\n"
        f"PrivateKey = {client_priv}\n"
        f"Address = {client_v4}/32, {client_v6}/128\n"
        f"DNS = {params.client_dns_1}, {params.client_dns_2}\n\n"
        "[Peer]\n"
        f"PublicKey = {params.server_pub_key}\n"
        f"PresharedKey = {psk}\n"
        f"AllowedIPs = {allowed_ips}\n"
        f"Endpoint = {endpoint}\n"
    )


def write_client_conf(out_path: Path, conf_text: str):
    out_path.write_text(conf_text, encoding="utf-8")
    os.chmod(out_path, 0o600)


def resetup_wireguard_noninteractive():
    p = Path(RESETUP_SCRIPT)
    if not p.exists():
        raise RuntimeError(f"RESETUP_SCRIPT not found: {RESETUP_SCRIPT}")
    sh(["python3", str(p)], check=True)


async def send_config_to_admin(bot, admin_id: int, conf_path: Path):
    conf_text = conf_path.read_text(encoding="utf-8", errors="ignore").strip()

    # Ready-to-paste message
    await bot.send_message(
        chat_id=admin_id,
        text=f"<pre>{conf_text}</pre>",
        parse_mode="HTML",
    )

    # .conf file attachment
    await bot.send_document(
        chat_id=admin_id,
        document=conf_path.open("rb"),
        filename=conf_path.name,
        caption=f"WireGuard config file: {conf_path.name}",
    )


async def regenerate_and_send(app: Application, requester_id: int):
    must_root()

    server_conf = WG_DIR / f"{WG_NIC}.conf"
    params_file = WG_DIR / "params"

    # 1) resetup
    resetup_wireguard_noninteractive()

    if not server_conf.exists():
        raise RuntimeError(f"Server config missing after resetup: {server_conf}")
    if not params_file.exists():
        raise RuntimeError(f"Params missing after resetup: {params_file}")

    params = parse_params_file(params_file)

    # 2) generate unique clients per admin
    used_v4 = set()
    generated: Dict[int, Path] = {}

    for admin_id in sorted(ADMINS):
        client_name = sanitize_client_name(f"adm_{admin_id}")
        client_priv, client_pub = wg_keypair()
        psk = wg_psk()

        client_v4 = next_client_ipv4(params.server_wg_ipv4, used_v4)
        last = int(client_v4.split(".")[-1])
        client_v6 = client_ipv6_from(params.server_wg_ipv6, last)

        conf_text = build_client_conf_text(params, client_priv, client_v4, client_v6, psk)
        out_path = OUT_DIR / f"{WG_NIC}-client-{client_name}.conf"
        write_client_conf(out_path, conf_text)

        add_peer_to_server_conf(server_conf, client_name, client_pub, psk, client_v4, client_v6)
        generated[admin_id] = out_path

    # Apply peers live
    sync_wg_conf(WG_NIC)

    # 3) send to admins: message + file, handle "chat not found"
    failed: List[Tuple[int, str]] = []
    for admin_id, path in generated.items():
        try:
            await send_config_to_admin(app.bot, admin_id, path)
        except (BadRequest, Forbidden) as e:
            failed.append((admin_id, str(e)))

    # Always show requester a summary
    endpoint = f"{bracket_if_ipv6(params.server_pub_ip)}:{params.server_port}"
    await app.bot.send_message(
        chat_id=requester_id,
        text=(
            "✅ Regenerated WireGuard configs.\n"
            f"- Interface: {WG_NIC}\n"
            f"- Endpoint: {endpoint}\n"
            f"- Admins: {len(ADMINS)}"
        ),
    )

    # If some admins didn't /start
    if failed:
        lines = ["⚠️ Could not send to these admins (they must /start the bot first):"]
        for admin_id, err in failed:
            lines.append(f"- {admin_id}: {err}")
        await app.bot.send_message(chat_id=requester_id, text="\n".join(lines))


def admin_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("🔁 Regenerate configs", callback_data="regen_configs")]]
    )


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user:
        return
    if not is_admin(user.id):
        await update.message.reply_text("Access denied.")
        return
    await update.message.reply_text("Admin panel:", reply_markup=admin_keyboard())


async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if not q or not q.from_user:
        return

    user_id = q.from_user.id
    if not is_admin(user_id):
        await q.answer("Access denied.", show_alert=True)
        return

    if q.data != "regen_configs":
        await q.answer()
        return

    await q.answer("Regenerating…", show_alert=False)

    async with regen_lock:
        try:
            await q.edit_message_text("⏳ Regenerating WireGuard configs…")
            await regenerate_and_send(context.application, requester_id=user_id)
            await q.edit_message_text("✅ Done. Sent unique configs to all admins.")
        except Exception as e:
            msg = f"❌ Failed: {e}"
            try:
                await q.edit_message_text(msg)
            except Exception:
                await context.application.bot.send_message(chat_id=user_id, text=msg)


async def main():
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN not set (use .env).")

    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CallbackQueryHandler(on_callback))

    await app.initialize()
    await app.start()
    await app.updater.start_polling()
    await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
