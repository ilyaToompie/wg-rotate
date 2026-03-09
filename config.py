import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

WG_NIC = os.environ.get("WG_NIC", "wg0")
WG_DIR = Path(os.environ.get("WG_DIR", "/etc/wireguard"))
OUT_DIR = Path(os.environ.get("OUT_DIR", "/root"))

RESETUP_SCRIPT = os.environ.get("RESETUP_SCRIPT", "./wg_autosetup.py")

STATE_PATH = Path(os.environ.get("STATE_PATH", "/etc/wireguard/wg_bot_state.json"))
LOG_PATH = Path(os.environ.get("LOG_PATH", "/var/log/wg_bot.log"))

OFFLINE_AFTER_SECONDS = int(os.environ.get("OFFLINE_AFTER_SECONDS", "180"))
PEER_CHECK_INTERVAL_SECONDS = int(os.environ.get("PEER_CHECK_INTERVAL_SECONDS", "30"))

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")

def load_admins():
    raw = os.environ.get("ADMIN_IDS", "")
    return {int(x.strip()) for x in raw.split(",") if x.strip().isdigit()}

ADMINS = load_admins()

