import json
import os
import secrets
import asyncio
from pathlib import Path
from typing import Dict, Any
from app.config import STORE_FILE, TEMPLATE_FILE

_lock = asyncio.Lock()


def _atomic_write_text(path: Path, text: str) -> None:
    """原子写入：先写同目录临时文件，落盘后再 os.replace 原子替换，
    防止容器异常退出时目标文件写一半损坏。"""
    tmp_path = path.with_name(path.name + ".tmp")
    tmp_path.write_text(text, encoding="utf-8")
    # 确保数据真正落盘再替换
    with open(tmp_path, "rb") as f:
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    os.replace(tmp_path, path)


def _default_store() -> Dict[str, Any]:
    return {
        "settings": {
            "sub_token": secrets.token_urlsafe(18),
            "sub_filename": "SubHub",
            "test_url": "https://www.gstatic.com/generate_204",
            "test_interval": 300,
            "test_tolerance": 50,
            "auto_emoji": True,
            "prepend_vps_tag": True,
            "udp_default": True,
            "sub_refresh_interval": 21600,
        },
        "nodes": [],
        "subscriptions": [],
        "custom_groups": [],
        "custom_rules": [],
    }

DEFAULT_BASE_TEMPLATE = """mixed-port: 7890
allow-lan: true
bind-address: "*"
mode: rule
log-level: info
ipv6: true
unified-delay: true
tcp-concurrent: true
external-controller: 0.0.0.0:9090

profile:
  store-selected: true
  store-fake-ip: true

sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  override-destination: true
  sniff:
    HTTP:
      ports: [80, 8080-8880]
      override-destination: true
    TLS:
      ports: [443, 8443]
    QUIC:
      ports: [443, 8443]

dns:
  enable: true
  listen: 0.0.0.0:1053
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
    - "*.local"
    - "+.msftconnecttest.com"
    - "+.msftncsi.com"
    - "ntp.*.com"
    - "time.*.com"
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  proxy-server-nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  nameserver-policy:
    "rule-set:private_domain,cn_domain":
      - https://dns.alidns.com/dns-query
      - https://doh.pub/dns-query
    "rule-set:geolocation-!cn":
      - https://dns.cloudflare.com/dns-query#🚀 节点选择
      - https://dns.google/dns-query#🚀 节点选择

rule-providers:
  private_domain:
    type: http
    interval: 86400
    behavior: domain
    format: mrs
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/private.mrs"
    path: ./ruleset/private_domain.mrs
  ai_domain:
    type: http
    interval: 86400
    behavior: domain
    format: mrs
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/category-ai-!cn.mrs"
    path: ./ruleset/ai_domain.mrs
  youtube_domain:
    type: http
    interval: 86400
    behavior: domain
    format: mrs
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/youtube.mrs"
    path: ./ruleset/youtube_domain.mrs
  google_domain:
    type: http
    interval: 86400
    behavior: domain
    format: mrs
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/google.mrs"
    path: ./ruleset/google_domain.mrs
  telegram_domain:
    type: http
    interval: 86400
    behavior: domain
    format: mrs
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/telegram.mrs"
    path: ./ruleset/telegram_domain.mrs
  netflix_domain:
    type: http
    interval: 86400
    behavior: domain
    format: mrs
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/netflix.mrs"
    path: ./ruleset/netflix_domain.mrs
  disney_domain:
    type: http
    interval: 86400
    behavior: domain
    format: mrs
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/disney.mrs"
    path: ./ruleset/disney_domain.mrs
  tiktok_domain:
    type: http
    interval: 86400
    behavior: domain
    format: mrs
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/tiktok.mrs"
    path: ./ruleset/tiktok_domain.mrs
  spotify_domain:
    type: http
    interval: 86400
    behavior: domain
    format: mrs
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/spotify.mrs"
    path: ./ruleset/spotify_domain.mrs
  apple_domain:
    type: http
    interval: 86400
    behavior: domain
    format: mrs
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/apple-cn.mrs"
    path: ./ruleset/apple_domain.mrs
  microsoft_domain:
    type: http
    interval: 86400
    behavior: domain
    format: mrs
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/microsoft@cn.mrs"
    path: ./ruleset/microsoft_domain.mrs
  ads_domain:
    type: http
    interval: 86400
    behavior: domain
    format: mrs
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/category-ads-all.mrs"
    path: ./ruleset/ads_domain.mrs
  geolocation-!cn:
    type: http
    interval: 86400
    behavior: domain
    format: mrs
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/geolocation-!cn.mrs"
    path: ./ruleset/geolocation-!cn.mrs
  cn_domain:
    type: http
    interval: 86400
    behavior: domain
    format: mrs
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/cn.mrs"
    path: ./ruleset/cn_domain.mrs
  private_ip:
    type: http
    interval: 86400
    behavior: ipcidr
    format: mrs
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/private.mrs"
    path: ./ruleset/private_ip.mrs
  telegram_ip:
    type: http
    interval: 86400
    behavior: ipcidr
    format: mrs
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/telegram.mrs"
    path: ./ruleset/telegram_ip.mrs
  cn_ip:
    type: http
    interval: 86400
    behavior: ipcidr
    format: mrs
    url: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/cn.mrs"
    path: ./ruleset/cn_ip.mrs

rules:
  - RULE-SET,private_domain,🎯 全球直连
  - RULE-SET,private_ip,🎯 全球直连,no-resolve
  - RULE-SET,ads_domain,🛑 广告拦截
  - DOMAIN-SUFFIX,openai.com,🤖 AI 专线
  - DOMAIN-SUFFIX,chatgpt.com,🤖 AI 专线
  - DOMAIN-SUFFIX,oaistatic.com,🤖 AI 专线
  - DOMAIN-SUFFIX,oaiusercontent.com,🤖 AI 专线
  - DOMAIN-SUFFIX,anthropic.com,🤖 AI 专线
  - DOMAIN-SUFFIX,claude.ai,🤖 AI 专线
  - DOMAIN-SUFFIX,gemini.google.com,🤖 AI 专线
  - DOMAIN-SUFFIX,bard.google.com,🤖 AI 专线
  - DOMAIN-SUFFIX,makersuite.google.com,🤖 AI 专线
  - DOMAIN-SUFFIX,aistudio.google.com,🤖 AI 专线
  - DOMAIN-SUFFIX,perplexity.ai,🤖 AI 专线
  - RULE-SET,ai_domain,🤖 AI 专线
  - RULE-SET,youtube_domain,📹 YouTube
  - RULE-SET,telegram_domain,📲 Telegram
  - RULE-SET,telegram_ip,📲 Telegram,no-resolve
  - RULE-SET,netflix_domain,🎬 流媒体服务
  - RULE-SET,disney_domain,🎬 流媒体服务
  - RULE-SET,tiktok_domain,🎬 流媒体服务
  - RULE-SET,spotify_domain,🎬 流媒体服务
  - RULE-SET,apple_domain,🍎 苹果与微软
  - RULE-SET,microsoft_domain,🍎 苹果与微软
  - RULE-SET,google_domain,🚀 节点选择
  - RULE-SET,geolocation-!cn,🚀 节点选择
  - RULE-SET,cn_domain,🎯 全球直连
  - RULE-SET,cn_ip,🎯 全球直连,no-resolve
  - MATCH,🐟 漏网之鱼
"""


def init_storage() -> None:
    if not TEMPLATE_FILE.exists():
        _atomic_write_text(TEMPLATE_FILE, DEFAULT_BASE_TEMPLATE)

    if not STORE_FILE.exists():
        _atomic_write_text(
            STORE_FILE, json.dumps(_default_store(), ensure_ascii=False, indent=2)
        )


async def load_store() -> Dict[str, Any]:
    init_storage()
    async with _lock:
        try:
            text = STORE_FILE.read_text(encoding="utf-8")
            data = json.loads(text)
            if not isinstance(data, dict):
                raise ValueError("store root is not a JSON object")
        except Exception:
            # 读取/解析失败：把坏文件改名留档，用默认结构重建，保证服务不崩
            try:
                if STORE_FILE.exists():
                    os.replace(
                        STORE_FILE,
                        STORE_FILE.with_name("store.json.corrupt"),
                    )
            except OSError:
                pass
            data = _default_store()
            _atomic_write_text(
                STORE_FILE, json.dumps(data, ensure_ascii=False, indent=2)
            )
            return data
        # 平滑兼容：老 store.json 缺 custom_groups/custom_rules 时补上
        if "custom_groups" not in data:
            data["custom_groups"] = []
        if "custom_rules" not in data:
            data["custom_rules"] = []
        # 一次性迁移：旧默认订阅名 SubHub-Mihomo → SubHub；
        # 仅当值仍为旧默认值时改写，用户自己改过的名字不动
        settings = data.get("settings", {})
        if settings.get("sub_filename") == "SubHub-Mihomo":
            settings["sub_filename"] = "SubHub"
            _atomic_write_text(
                STORE_FILE, json.dumps(data, ensure_ascii=False, indent=2)
            )
        return data


async def save_store(data: Dict[str, Any]) -> None:
    async with _lock:
        _atomic_write_text(
            STORE_FILE, json.dumps(data, ensure_ascii=False, indent=2)
        )


def load_template() -> str:
    init_storage()
    return TEMPLATE_FILE.read_text(encoding="utf-8")


def save_template(content: str) -> None:
    _atomic_write_text(TEMPLATE_FILE, content)
