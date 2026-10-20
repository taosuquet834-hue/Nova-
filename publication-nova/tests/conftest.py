import os
import sys
from pathlib import Path

# Automated tests run on the separate, trivially easy "-easy" network (see core.EASY).
# This must be set before novacoin.core is imported, including in child processes.
os.environ["NOVA_EASY"] = "1"
sys.path.insert(0, str(Path(__file__).resolve().parent))
