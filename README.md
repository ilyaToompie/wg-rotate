# WireGuard installer
# My personal project, for my purposes
fork of https://github.com/angristan/wireguard-install

quick install/reinstall of wireguard for my server, with random/default settings, then send the result to admins

bot will ignore anyone who is not the admin

.env example: 
TELEGRAM_BOT_TOKEN=xxxx
ADMIN_IDS=111111111,222222222
RESETUP_SCRIPT=./wg_autosetup.py

# optional overrides
OFFLINE_AFTER_SECONDS=180
PEER_CHECK_INTERVAL_SECONDS=30
LOG_PATH=/var/log/wg_bot.log
STATE_PATH=/etc/wireguard/wg_bot_state.json
WG_NIC=wg0
