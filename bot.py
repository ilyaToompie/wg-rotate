import asyncio
from telegram.ext import Application, CommandHandler

from config import TOKEN, PEER_CHECK_INTERVAL_SECONDS
from telegram.handlers import cmd_start
from telegram.jobs import peer_check_job
from logging_utils import log_event

async def main():

    app = Application.builder().token(TOKEN).build()

    app.add_handler(CommandHandler("start", cmd_start))

    app.job_queue.run_repeating(
        peer_check_job,
        interval=PEER_CHECK_INTERVAL_SECONDS,
        first=10
        
    )

    log_event("bot_start")

    await app.initialize()
    await app.start()
    await app.updater.start_polling()

    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())