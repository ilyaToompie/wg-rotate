#!/usr/bin/env python3

import asyncio
import json
import os
import re
import secrets
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Tuple, Optional

from dotenv import load_dotenv
from telegram import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    ReplyKeyboardMarkup,
    KeyboardButton,
    Update,
)
from telegram.error import BadRequest, Forbidden
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# ----------------------------
# Load env
# ----------------------------
load_dotenv()

# ----------------------------
# Config
# ----------------------------
WG_NIC = os.environ.get("WG_NIC", "wg0")
WG_DIR = Path(os.environ.get("WG_DIR", "/etc/wireguard"))
OUT_DIR = Path(os.environ.get("OUT_DIR", "/root"))

RESETUP_SCRIPT = os.environ.get("RESETUP_SCRIPT", "./wg_autosetup.py")

STATE_PATH = Path(os.environ.get("STATE_PATH", "/etc/wireguard/wg_bot_state.json"))
LOG_PATH = Path(os.environ.get("LOG_PATH", "/var/log/wg_bot.log"))

# offline threshold: handshake older than this => offline
OFFLINE_AFTER_SECONDS = int(os.environ.get("OFFLINE_AFTER_SECONDS", "180"))
PEER_CHECK_INTERVAL_SECONDS = int(os.environ.get("PEER_CHECK_INTERVAL_SECONDS", "30"))

regen_lock = asyncio.Lock()


def sh(cmd: List[str], check=True, capture=True) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def must_root():
    if os.geteuid() != 0:
        raise RuntimeError("Bot must run as root (wg/iptables/systemd). Run: sudo -E python3 wg_bot.py")


def now_iso() -> str:
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S") #my local time


def log_event(event: str, **fields):
    """
    Append one JSON line to LOG_PATH.
    """
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {"ts": now_iso(), "event": event, **fields}
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def load_admins() -> set[int]:
    raw = os.environ.get("ADMIN_IDS", "")
    if not raw:
        raise RuntimeError("ADMIN_IDS not set in .env")
    return {int(x.strip()) for x in raw.split(",") if x.strip().isdigit()}


ADMINS = load_admins()


def is_admin(user_id: int) -> bool:
    return user_id in ADMINS


def sanitize_client_name(name: str) -> str:
    name = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
    return name[:15] if len(name) > 15 else name


# ----------------------------
# State (regen info + peer status)
# ----------------------------
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


def read_state() -> dict:
    if not STATE_PATH.exists():
        return {
            "last_regen_ts": None,
            "endpoint": None,
            "generation_number": None,
            "admin_peers": {},  # admin_id -> {"public_key": "...", "last_handshake": 0, "online": False}
        }
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {
            "last_regen_ts": None,
            "endpoint": None,
            "generation_number": None,
            "admin_peers": {},
        }


def write_state(state: dict):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, STATE_PATH)


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

    # Ready-to-paste
    await bot.send_message(
        chat_id=admin_id,
        text=f"<pre>{conf_text}</pre>",
        parse_mode="HTML",
    )

    # .conf file
    await bot.send_document(
        chat_id=admin_id,
        document=conf_path.open("rb"),
        filename=conf_path.name,
        caption=f"WireGuard config file: {conf_path.name}",
    )


# ----------------------------
# Admin keyboard (permanent)
# ----------------------------
BTN_REGEN = "🔁 Regenerate configs"
BTN_CHECK = "✅ Check last config update"
BTN_LOGS = "📜 Logs"

ADMIN_KB = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(BTN_REGEN), KeyboardButton(BTN_CHECK)],
        [KeyboardButton(BTN_LOGS)],
    ],
    resize_keyboard=True,
    is_persistent=True,
)


def admin_inline_keyboard() -> InlineKeyboardMarkup:
    # Keep inline too (optional). You can remove this if you only want reply keyboard.
    return InlineKeyboardMarkup([[InlineKeyboardButton(BTN_REGEN, callback_data="regen_configs")]])


# ----------------------------
# Peer monitoring
# ----------------------------
def wg_dump() -> List[dict]:
    """
    Returns peer rows from: wg show <nic> dump
    Format:
      interface: priv pub listen fwmark
      peer lines: peer_pub psk endpoint allowed_ips latest_handshake rx tx keepalive
    """
    r = sh(["wg", "show", WG_NIC, "dump"], check=True, capture=True)
    lines = (r.stdout or "").splitlines()
    peers = []
    for i, line in enumerate(lines):
        cols = line.split("\t")
        if i == 0:
            continue
        if len(cols) < 9:
            continue
        peers.append(
            {
                "public_key": cols[0],
                "latest_handshake": int(cols[5]) if cols[5].isdigit() else 0,
                "rx": int(cols[6]) if cols[6].isdigit() else 0,
                "tx": int(cols[7]) if cols[7].isdigit() else 0,
            }
        )
    return peers


async def peer_check_job(context: ContextTypes.DEFAULT_TYPE):
    """
    Periodically checks admin peers and logs online->offline transitions.
    Uses STATE_PATH mapping admin_id -> public_key.
    """
    try:
        state = read_state()
        admin_peers = state.get("admin_peers", {})
        if not admin_peers:
            return  # nothing to monitor yet

        peer_rows = wg_dump()
        by_pub = {p["public_key"]: p for p in peer_rows}
        now = int(time.time())

        changed = False

        for admin_id_str, info in admin_peers.items():
            pub = info.get("public_key")
            if not pub:
                continue

            row = by_pub.get(pub)
            hs = int(row["latest_handshake"]) if row else 0

            was_online = bool(info.get("online", False))
            is_online = (hs > 0) and ((now - hs) <= OFFLINE_AFTER_SECONDS)

            # update stored handshake
            info["last_handshake"] = hs

            # transitions
            if was_online and not is_online:
                log_event("peer_offline", admin_id=int(admin_id_str), public_key=pub, last_handshake=hs)
                info["online"] = False
                changed = True
            elif (not was_online) and is_online:
                # Optional, but useful
                log_event("peer_online", admin_id=int(admin_id_str), public_key=pub, last_handshake=hs)
                info["online"] = True
                changed = True

        if changed:
            state["admin_peers"] = admin_peers
            write_state(state)

    except Exception as e:
        # Keep bot alive; log internal errors
        log_event("peer_check_error", error=str(e))


# ----------------------------
# Core action: regenerate + broadcast
# ----------------------------
async def regenerate_and_send(app: Application, requester_id: int):
    must_root()

    state = read_state()
    state["generation_id"] += 1

    server_conf = WG_DIR / f"{WG_NIC}.conf"
    params_file = WG_DIR / "params"

    log_event("regen_start", requester_id=requester_id)

    # 1) resetup
    resetup_wireguard_noninteractive()

    if not server_conf.exists():
        raise RuntimeError(f"Server config missing after resetup: {server_conf}")
    if not params_file.exists():
        raise RuntimeError(f"Params missing after resetup: {params_file}")

    params = parse_params_file(params_file)
    endpoint = f"{bracket_if_ipv6(params.server_pub_ip)}:{params.server_port}"

    # 2) generate unique clients per admin
    used_v4 = set()
    generated: Dict[int, Path] = {}
    peer_pubkeys: Dict[int, str] = {}

    for admin_id in sorted(ADMINS):
        client_name = sanitize_client_name(f"adm_{admin_id}")
        client_priv, client_pub = wg_keypair()
        psk = wg_psk()

        client_v4 = next_client_ipv4(params.server_wg_ipv4, used_v4)
        last = int(client_v4.split(".")[-1])
        client_v6 = client_ipv6_from(params.server_wg_ipv6, last)

        conf_text = build_client_conf_text(params, client_priv, client_v4, client_v6, psk)
        out_path = OUT_DIR / f"{WG_NIC}-client-{client_name}-{state["generation_id"]}.conf"
        write_client_conf(out_path, conf_text)

        add_peer_to_server_conf(server_conf, client_name, client_pub, psk, client_v4, client_v6)

        generated[admin_id] = out_path
        peer_pubkeys[admin_id] = client_pub

    # Apply peers live
    sync_wg_conf(WG_NIC)

    # Update state
    state = read_state()
    state["last_regen_ts"] = now_iso()
    state["endpoint"] = endpoint
    state["admin_peers"] = {
        str(admin_id): {
            "public_key": peer_pubkeys[admin_id],
            "last_handshake": 0,
            "online": False,
        }
        for admin_id in ADMINS
    }
    write_state(state)

    # 3) send to admins: message + file, ignore non-started chats but report to requester
    failed: List[Tuple[int, str]] = []
    for admin_id, path in generated.items():
        try:
            await send_config_to_admin(app.bot, admin_id, path)
        except (BadRequest, Forbidden) as e:
            failed.append((admin_id, str(e)))

    log_event("regen_done", requester_id=requester_id, endpoint=endpoint, admins=len(ADMINS), failed=len(failed))

    # Notify requester (always)
    await app.bot.send_message(
        chat_id=requester_id,
        text=(
            "✅ Regenerated WireGuard configs.\n"
            f"- Interface: {WG_NIC}\n"
            f"- Endpoint: {endpoint}\n"
            f"- Admins: {len(ADMINS)}"
        ),
    )

    if failed:
        lines = ["⚠️ Could not send to these admins (they must /start the bot first):"]
        for admin_id, err in failed:
            lines.append(f"- {admin_id}: {err}")
        await app.bot.send_message(chat_id=requester_id, text="\n".join(lines))


# ----------------------------
# Commands / handlers
# ----------------------------
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user or not is_admin(user.id):
        # Ignore non-admin completely
        return

    await update.message.reply_text(
        "Admin panel:",
        reply_markup=ADMIN_KB,
    )


async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if not q or not q.from_user:
        return

    user_id = q.from_user.id
    if not is_admin(user_id):
        # Ignore
        return

    if q.data != "regen_configs":
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


async def handle_admin_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user or not is_admin(user.id):
        # ignore non-admin
        return

    text = (update.message.text or "").strip()

    if text == BTN_REGEN:
        async with regen_lock:
            try:
                await update.message.reply_text("⏳ Regenerating WireGuard configs…")
                await regenerate_and_send(context.application, requester_id=user.id)
                await update.message.reply_text("✅ Done.", reply_markup=ADMIN_KB)
            except Exception as e:
                await update.message.reply_text(f"❌ Failed: {e}", reply_markup=ADMIN_KB)

    elif text == BTN_CHECK:
        state = read_state()
        last_ts = state.get("last_regen_ts")
        endpoint = state.get("endpoint")
        if last_ts and endpoint:
            await update.message.reply_text(
                f"Last config update:\n- Time (UTC): {last_ts}\n- Endpoint: {endpoint}",
                reply_markup=ADMIN_KB,
            )
        else:
            await update.message.reply_text("No config update recorded yet.", reply_markup=ADMIN_KB)

    elif text == BTN_LOGS:
        # Return last N log lines (JSONL)
        N = 30
        if not LOG_PATH.exists():
            await update.message.reply_text("No logs yet.", reply_markup=ADMIN_KB)
            return

        lines = LOG_PATH.read_text(encoding="utf-8", errors="ignore").splitlines()
        tail = lines[-N:]
        # make it readable (not raw json)
        pretty = []
        for ln in tail:
            try:
                obj = json.loads(ln)
                pretty.append(f"{obj.get('ts')} | {obj.get('event')} | {json.dumps({k:v for k,v in obj.items() if k not in ('ts','event')}, ensure_ascii=False)}")
            except Exception:
                pretty.append(ln)

        msg = "\n".join(pretty) if pretty else "No logs yet."
        # send as <pre> to preserve formatting
        await update.message.reply_text(f"<pre>{msg}</pre>", parse_mode="HTML", reply_markup=ADMIN_KB)

    else:
        # unknown admin message: no noise, but keep keyboard
        await update.message.reply_text("OK.", reply_markup=ADMIN_KB)


# ----------------------------
# Main
# ----------------------------
async def main():
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN not set (use .env).")

    must_root()

    app = Application.builder().token(token).build()

    # Admin start (non-admin ignored)
    app.add_handler(CommandHandler("start", cmd_start))

    # Inline callback (optional)
    app.add_handler(CallbackQueryHandler(on_callback))

    # Admin keyboard commands
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_admin_text))

    # Peer monitoring job
    app.job_queue.run_repeating(peer_check_job, interval=PEER_CHECK_INTERVAL_SECONDS, first=10)

    log_event("bot_start", admins=len(ADMINS), wg_nic=WG_NIC)

    await app.initialize()
    await app.start()
    await app.updater.start_polling()
    await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log_event("bot_stop")
