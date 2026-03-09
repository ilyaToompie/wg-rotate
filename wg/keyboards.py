from utils.shell import sh

def wg_keypair():
    priv = sh(["wg", "genkey"]).stdout.strip()
    pub = sh(["bash", "-lc", f"echo -n '{priv}' | wg pubkey"]).stdout.strip()
    return priv, pub

def wg_psk():
    return sh(["wg", "genpsk"]).stdout.strip()