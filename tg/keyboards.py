from telegram import ReplyKeyboardMarkup, KeyboardButton

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

