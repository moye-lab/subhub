import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("DATA_DIR", str(BASE_DIR / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)

STORE_FILE = DATA_DIR / "store.json"
TEMPLATE_FILE = DATA_DIR / "base_template.yaml"

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
