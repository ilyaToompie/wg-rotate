from telegram import Update
from telegram.ext import ContextTypes
from telegram.keyboards import ADMIN_KB
from config import ADMINS

def is_admin(uid: int):
    return uid in ADMINS

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user

    if not user or not is_admin(user.id):
        return

    await update.message.reply_text(
        "Admin panel:",
        reply_markup=ADMIN_KB
    )