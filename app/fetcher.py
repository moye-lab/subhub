import re
import yaml
import httpx
from datetime import datetime, timezone
from typing import List, Dict, Any
from app.parser import safe_b64decode, parse_single_line, decorate_name
from app.fingerprint import compute_fingerprint


async def fetch_single_subscription(
    sub: Dict[str, Any], settings: Dict[str, Any]
) -> List[Dict[str, Any]]:
    url = sub.get("url", "").strip()
    if not url:
        return sub.get("cached_proxies", [])

    prefix = sub.get("prefix", "").strip()
    exclude_regex = sub.get("exclude_regex", "").strip()
    auto_emoji = settings.get("auto_emoji", True)
    udp_default = settings.get("udp_default", True)

    headers = {"User-Agent": "clash.meta/v1.18.0 SubHub/1.0"}
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, verify=False) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            text = resp.text.strip()
    except Exception:
        return sub.get("cached_proxies", [])

    proxies: List[Dict[str, Any]] = []

    # 1. Try Clash YAML format
    if "proxies:" in text:
        try:
            loaded = yaml.safe_load(text)
            if isinstance(loaded, dict) and isinstance(loaded.get("proxies"), list):
                for p in loaded["proxies"]:
                    if isinstance(p, dict) and "name" in p and "server" in p:
                        raw_name = str(p["name"])
                        if exclude_regex and re.search(exclude_regex, raw_name):
                            continue
                        final_name = f"{prefix}{raw_name}" if prefix else raw_name
                        p["name"] = decorate_name(
                            final_name,
                            vps_tag="",
                            custom_name="",
                            auto_emoji=auto_emoji,
                            prepend_vps_tag=False,
                        )
                        p["fingerprint"] = compute_fingerprint(p)
                        proxies.append(p)
        except Exception:
            pass

    # 2. Try Base64 or Plain URI lines
    if not proxies:
        if "://" not in text[:60]:
            try:
                decoded = safe_b64decode(text)
                if "://" in decoded:
                    text = decoded
            except Exception:
                pass

        for line in text.splitlines():
            p = parse_single_line(
                line,
                vps_tag="",
                custom_name="",
                auto_emoji=False,
                prepend_vps_tag=False,
                udp_default=udp_default,
            )
            if p:
                raw_name = str(p["name"])
                if exclude_regex and re.search(exclude_regex, raw_name):
                    continue
                final_name = f"{prefix}{raw_name}" if prefix else raw_name
                p["name"] = decorate_name(
                    final_name,
                    vps_tag="",
                    custom_name="",
                    auto_emoji=auto_emoji,
                    prepend_vps_tag=False,
                )
                p["fingerprint"] = compute_fingerprint(p)
                proxies.append(p)

    if proxies:
        sub["cached_proxies"] = proxies
        sub["last_updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return sub.get("cached_proxies", [])
