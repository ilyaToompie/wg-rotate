from utils.shell import sh
from config import RESETUP_SCRIPT
from pathlib import Path

def resetup_wireguard():
    p = Path(RESETUP_SCRIPT)

    if not p.exists():
        raise RuntimeError("RESETUP_SCRIPT missing")

    sh(["python3", str(p)])

def sync_wg_conf(nic):
    sh(["bash", "-lc", f"wg syncconf {nic} <(wg-quick strip {nic})"])