import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from typing import List, Dict, Any, Optional

from core.config import settings

logger = logging.getLogger(__name__)

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")


def _find_harvester_binary():
    """Finds theHarvester executable across PATH, lowercased names, or WSL."""
    # 1. Configured or System PATH (standard casing and lowercase apt name)
    for name in [settings.THEHARVESTER_BIN, "theHarvester", "theharvester", "/usr/bin/theHarvester", "/usr/bin/theharvester"]:
        found = shutil.which(name)
        if found:
            return found

    # 2. WSL Fallback Check
    try:
        for wsl_name in ["theHarvester", "theharvester"]:
            proc = subprocess.run(["wsl", "which", wsl_name], capture_output=True, text=True, timeout=2)
            if proc.returncode == 0 and proc.stdout.strip():
                logger.info(f"Detected theHarvester inside WSL as '{wsl_name}'")
                return ["wsl", wsl_name]
    except Exception:
        pass

    return None


def run_harvester(domain: str, timeout: int = 60) -> List[Dict[str, Any]]:
    """
    Submodule 1: theHarvester CLI integration with multi-source fallback.
    Executes theHarvester binary, parses JSON artifact, and falls back to stdout regex extraction.
    """
    harvester_bin = _find_harvester_binary()
    if not harvester_bin:
        logger.info(f"[people.harvester] theHarvester binary not found on system PATH; relying on native OSINT engines")
        return []

    bin_str = harvester_bin if isinstance(harvester_bin, str) else " ".join(harvester_bin)
    logger.info(f"[people.harvester] Executing theHarvester on '{domain}' via '{bin_str}' (timeout: {timeout}s)")

    results: List[Dict[str, Any]] = []
    seen_emails = set()

    with tempfile.TemporaryDirectory() as tmpdir:
        out_base = os.path.join(tmpdir, "harvester_out")
        json_file = f"{out_base}.json"

        base_cmd = [harvester_bin] if isinstance(harvester_bin, str) else list(harvester_bin)

        # Standard, highly reliable free sources supported across all theHarvester versions
        sources = "bing,duckduckgo,yahoo,crtsh,otx,hackertarget"
        cmd = base_cmd + [
            "-d", domain,
            "-b", sources,
            "-l", "200",
            "-f", out_base,
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
            )

            if proc.returncode != 0 and proc.stderr:
                logger.warning(f"[people.harvester] theHarvester notice (exit code {proc.returncode}): {proc.stderr.strip()[:300]}")

            # 1. Parse JSON output artifact if created
            if os.path.exists(json_file):
                try:
                    with open(json_file, "r", encoding="utf-8", errors="ignore") as f:
                        data = json.load(f)

                        for email in data.get("emails", []):
                            if isinstance(email, str) and "@" in email:
                                em_clean = email.strip().lower()
                                if em_clean not in seen_emails:
                                    seen_emails.add(em_clean)
                                    results.append({
                                        "name": "",
                                        "email": em_clean,
                                        "confidence": 80,
                                        "source": "theHarvester:json",
                                    })
                except Exception as e:
                    logger.debug(f"[people.harvester] JSON parse failed: {e}")

            # 2. Fallback: Parse stdout with regex if JSON was incomplete
            full_output = f"{proc.stdout or ''} {proc.stderr or ''}"
            for match in EMAIL_REGEX.findall(full_output):
                em_clean = match.strip().lower().rstrip(".")
                if domain in em_clean and em_clean not in seen_emails:
                    seen_emails.add(em_clean)
                    results.append({
                        "name": "",
                        "email": em_clean,
                        "confidence": 75,
                        "source": "theHarvester:stdout",
                    })

            logger.info(f"[people.harvester] theHarvester completed for '{domain}': {len(results)} email/identity findings discovered (exit code: {proc.returncode})")

        except subprocess.TimeoutExpired:
            logger.warning(f"[people.harvester] theHarvester timed out after {timeout}s for '{domain}'")
        except Exception as e:
            logger.warning(f"[people.harvester] theHarvester execution failed for '{domain}': {e}")

    return results

