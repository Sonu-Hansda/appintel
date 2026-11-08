import json
import subprocess
import re
from pathlib import Path
from typing import List, Optional

def run_command(cmd: List[str], timeout: int=300) ->tuple[str, str, int]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode

    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", 1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", 127

def validate_domain(domain: str) -> bool:
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, domain)) and len(domain) <= 253

def save_json(data, filepath: str) -> None:
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)

    if hasattr(data, 'model_dump'):
        data_dict = data.model_dump()
    elif hasattr(data, 'dict'):
        data_dict = data.dict()
    else:
        data_dict = data

    def json_serial(obj):
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        raise TypeError(f"Type {type(obj)} not serializable")

    with open(filepath, 'w') as f:
        json.dump(data_dict, f, indent=2, default=json_serial)

    print(f"[+] Results saved to: {filepath}")