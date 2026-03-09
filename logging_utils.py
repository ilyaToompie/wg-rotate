import json
from datetime import datetime, timezone, timedelta
from config import LOG_PATH

def now_iso():
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")

def log_event(event: str, **fields):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    record = {"ts": now_iso(), "event": event, **fields}

    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

        