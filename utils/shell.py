import subprocess
from typing import List

def sh(cmd: List[str], check=True, capture=True):
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )