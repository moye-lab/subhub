import re
import base64
import json
import yaml
from typing import List, Dict, Any, Tuple
from urllib.parse import quote, urlencode
from app.storage import load_template
from app.parser import parse_single_line
from app.fingerprint import compute_fingerprint

REGION_GROUPS_SPEC = [
    ("🇺🇸 美国节点", r"(?i)(🇺🇸|us|usa|america|united\s*states|美国|洛杉矶|圣何塞|西雅图|硅谷|纽约|芝加哥)"),
    ("🇯🇵 日本节点", r"(?i)(🇯🇵|jp|japan|日本|东京|大阪|埼玉|软银|IIJ)"),
    ("🇸🇬 狮城节点", r"(?i)(🇸🇬|sg|singapore|新加坡|狮城)"),
    ("🇭🇰 香港节点", r"(?i)(🇭🇰|hk|hong\s*kong|香港|深港|沪港)"),
    ("🇹🇼 台湾节点", r"(?i)(🇹🇼|tw|taiwan|台湾|台北|新北|彰化)"),
]

AI_EXCLUDE_REGEX = r"(?i)(🇭🇰|hk|hong\s*kong|香港|cn|china|中国|mo|macau|澳门|🇷🇺|ru|russia|俄罗斯|莫斯科)"


def collect_all_proxies(store: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    settings = store.get("settings", {})
    auto_emoji = settings.get("auto_emoji", True)
    prepend_vps_tag = settings.get("prepend_vps_tag", True)
    udp_default = settings.get("udp_default", True)

    raw_nodes = [n for n in store.get("nodes", []) if n.get("enabled", True)]
    raw_nodes.sort(key=lambda x: int(x.get("priority", 10)))

    all_proxies: List[Dict[str, Any]] = []
    raw_uris: List[str] = []

    for node in raw_nodes:
        uri = node.get("uri", "").strip()
        if uri.startswith(("vless://", "hysteria2://", "hy2://", "tuic://", "trojan://", "ss://", "vmess://", "socks5://")):
            raw_uris.append(uri)
        p = parse_single_line(
            line=uri,
            vps_tag=node.get("vps_tag", ""),
            custom_name=node.get("name", ""),
            auto_emoji=auto_emoji,
            prepend_vps_tag=prepend_vps_tag,
            udp_default=udp_default,
        )
        if p:
            # 挂载原始分享链接：base64 输出时只替换 #fragment 为最终修饰名。
            # YAML 行不挂（走 dict 反向拼装分支）。
            if "://" in uri:
                p["_raw_uri"] = uri
            all_proxies.append(p)

    for sub in store.get("subscriptions", []):
        if sub.get("enabled", True):
            for p in sub.get("cached_proxies", []):
                all_proxies.append(dict(p))

    # Deduplicate by connection fingerprint: same line, different display name = same node.
    # (A node manually added AND pulled from a remote sub appears only once.)
    seen_fp: Dict[str, bool] = {}
    unique_proxies: List[Dict[str, Any]] = []
    for p in all_proxies:
        fp = p.get("fingerprint") or compute_fingerprint(p)
        p["fingerprint"] = fp
        if fp in seen_fp:
            continue
        seen_fp[fp] = True
        unique_proxies.append(p)
    all_proxies = unique_proxies

    # Deduplicate names (mihomo requires unique proxy names)
    seen_names: Dict[str, int] = {}
    for p in all_proxies:
        base_name = str(p.get("name", "Node")).strip()
        if base_name not in seen_names:
            seen_names[base_name] = 1
        else:
            seen_names[base_name] += 1
            p["name"] = f"{base_name} #{seen_names[base_name]}"

    return all_proxies, raw_uris


def proxy_dict_to_share_uri(p: Dict[str, Any]) -> str:
    """把 Mihomo proxy dict 还原为标准分享链接。

    - 自建节点（带 _raw_uri）：保留原始链接全部参数，仅把 #fragment
      替换为 collect 阶段修饰好的最终名称（含 [VPS标签] / 国旗 Emoji）；
    - 远程订阅缓存节点（无原始 URI）：按协议从 dict 反向拼装标准分享链接。
    两种路径的 fragment 都是最终修饰名，保证各客户端看到的名称一致。
    """
    name = quote(str(p.get("name", "") or "Node"), safe="")
    raw = (p.get("_raw_uri") or "").strip()
    if raw and "://" in raw:
        return f"{raw.split('#', 1)[0]}#{name}"

    server = p.get("server", "")
    port = p.get("port", "")
    ptype = str(p.get("type", "")).lower()

    def _qs(pairs) -> str:
        return urlencode([(k, v) for k, v in pairs if v not in (None, "")])

    if ptype == "vless":
        ro = p.get("reality-opts", {}) or {}
        if ro.get("public-key"):
            security = "reality"
        elif p.get("tls"):
            security = "tls"
        else:
            security = "none"
        qs = _qs([
            ("security", security),
            ("type", p.get("network", "tcp")),
            ("sni", p.get("servername", "")),
            ("fp", p.get("client-fingerprint", "")),
            ("pbk", ro.get("public-key", "")),
            ("sid", ro.get("short-id", "")),
            ("flow", p.get("flow", "")),
        ])
        return f"vless://{quote(str(p.get('uuid', '')), safe='')}@{server}:{port}?{qs}#{name}"

    if ptype == "hysteria2":
        qs = _qs([
            ("sni", p.get("sni", "")),
            ("insecure", "1" if p.get("skip-cert-verify") else "0"),
            ("obfs", p.get("obfs", "")),
            ("obfs-password", p.get("obfs-password", "")),
        ])
        return (
            f"hysteria2://{quote(str(p.get('password', '')), safe='')}"
            f"@{server}:{port}?{qs}#{name}"
        )

    if ptype == "trojan":
        qs = _qs([
            ("sni", p.get("sni", "")),
            ("type", p.get("network", "tcp")),
            ("insecure", "1" if p.get("skip-cert-verify") else "0"),
        ])
        return (
            f"trojan://{quote(str(p.get('password', '')), safe='')}"
            f"@{server}:{port}?{qs}#{name}"
        )

    if ptype == "tuic":
        qs = _qs([
            ("sni", p.get("sni", "")),
            ("congestion_control", p.get("congestion-controller", "")),
            ("udp_relay_mode", p.get("udp-relay-mode", "")),
        ])
        userinfo = (
            f"{quote(str(p.get('uuid', '')), safe='')}:"
            f"{quote(str(p.get('password', '')), safe='')}"
        )
        return f"tuic://{userinfo}@{server}:{port}?{qs}#{name}"

    if ptype == "ss":
        user = base64.urlsafe_b64encode(
            f"{p.get('cipher', '')}:{p.get('password', '')}".encode("utf-8")
        ).decode("ascii").rstrip("=")
        return f"ss://{user}@{server}:{port}#{name}"

    if ptype == "vmess":
        ws = p.get("ws-opts", {}) or {}
        host = ((ws.get("headers", {}) or {}).get("Host", "")
                or p.get("servername", ""))
        path = (ws.get("path", "")
                or (p.get("grpc-opts", {}) or {}).get("grpc-service-name", ""))
        data = {
            "v": "2",
            "ps": str(p.get("name", "")),
            "add": server,
            "port": str(port),
            "id": p.get("uuid", ""),
            "aid": str(p.get("alterId", 0)),
            "scy": p.get("cipher", "auto"),
            "net": p.get("network", "tcp"),
            "type": "none",
            "host": host,
            "path": path,
            "tls": "tls" if p.get("tls") else "",
        }
        b64 = base64.b64encode(
            json.dumps(data, ensure_ascii=False).encode("utf-8")
        ).decode("ascii")
        return f"vmess://{b64}"

    if ptype == "socks5":
        user = str(p.get("username", ""))
        auth = (
            f"{quote(user, safe='')}:{quote(str(p.get('password', '')), safe='')}@"
            if user else ""
        )
        return f"socks5://{auth}{server}:{port}#{name}"

    return ""


def _match_custom_group_nodes(
    proxies: List[Dict[str, Any]], group: Dict[str, Any]
) -> List[str]:
    """按 vps_filter（节点名中的 [tag] 或 vps_tag 字段）与 name_regex 筛选节点名。
    两个条件都填写时取交集；都留空则匹配全部节点。"""
    vf = (group.get("vps_filter") or "").strip()
    rx = (group.get("name_regex") or "").strip()
    compiled = None
    if rx:
        try:
            compiled = re.compile(rx)
        except re.error:
            compiled = None
    matched: List[str] = []
    for p in proxies:
        name = str(p.get("name", ""))
        if vf and not (f"[{vf}]" in name or p.get("vps_tag") == vf):
            continue
        if compiled and not compiled.search(name):
            continue
        matched.append(name)
    return matched


def build_custom_groups(
    proxies: List[Dict[str, Any]],
    settings: Dict[str, Any],
    custom_groups: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """把用户自定义分流组转成 Mihomo proxy-groups 条目。"""
    test_url = settings.get("test_url", "https://www.gstatic.com/generate_204")
    test_interval = int(settings.get("test_interval", 300))
    test_tolerance = int(settings.get("test_tolerance", 50))
    out: List[Dict[str, Any]] = []
    seen_names: set = set()
    for cg in custom_groups or []:
        if not cg.get("enabled", True):
            continue
        name = (cg.get("name") or "").strip()
        if not name or name in seen_names:
            continue
        seen_names.add(name)
        gtype = (cg.get("type") or "select").strip().lower()
        if gtype not in ("select", "url-test", "fallback"):
            gtype = "select"
        matched = _match_custom_group_nodes(proxies, cg)
        if cg.get("include_direct") and "DIRECT" not in matched:
            matched.append("DIRECT")
        if not matched:
            # 防空组保护：绝不输出空 proxies
            matched = ["DIRECT"]
        group: Dict[str, Any] = {"name": name, "type": gtype, "proxies": matched}
        if gtype == "url-test":
            group.update(
                {
                    "url": test_url,
                    "interval": test_interval,
                    "tolerance": test_tolerance,
                    "lazy": True,
                }
            )
        elif gtype == "fallback":
            group.update({"url": test_url, "interval": 180, "lazy": True})
        out.append(group)
    return out


def _build_custom_mihomo_rules(
    custom_rules: List[Dict[str, Any]], group_names: set
) -> List[str]:
    """自定义规则转 Mihomo 规则字符串。目标不存在时回退主选择组防启动报错。"""
    out: List[str] = []
    for r in custom_rules or []:
        if not r.get("enabled", True):
            continue
        value = (r.get("value") or "").strip()
        if not value:
            continue
        rule_type = (r.get("rule_type") or "DOMAIN-SUFFIX").strip().upper()
        target = (r.get("target") or "").strip()
        if target not in group_names and target not in ("DIRECT", "REJECT"):
            target = "🚀 节点选择"
        if rule_type == "IP-CIDR":
            out.append(f"IP-CIDR,{value},{target},no-resolve")
        else:
            out.append(f"{rule_type},{value},{target}")
    return out


def build_proxy_groups(
    proxies: List[Dict[str, Any]],
    settings: Dict[str, Any],
    custom_groups: List[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    test_url = settings.get("test_url", "https://www.gstatic.com/generate_204")
    test_interval = int(settings.get("test_interval", 300))
    test_tolerance = int(settings.get("test_tolerance", 50))

    all_names = [p["name"] for p in proxies]
    if not all_names:
        all_names = ["DIRECT"]

    # 1. Dynamically build non-empty region groups
    active_region_groups: List[Dict[str, Any]] = []
    active_region_names: List[str] = []

    for group_name, pattern in REGION_GROUPS_SPEC:
        matched = [name for name in all_names if re.search(pattern, name)]
        if matched:
            active_region_names.append(group_name)
            active_region_groups.append(
                {
                    "name": group_name,
                    "type": "url-test",
                    "url": test_url,
                    "interval": test_interval,
                    "tolerance": test_tolerance,
                    "lazy": True,
                    "proxies": matched,
                }
            )

    # 2. Filter AI nodes (exclude HK/CN/MO/RU)
    ai_nodes = [
        name for name in all_names if not re.search(AI_EXCLUDE_REGEX, name) and name != "DIRECT"
    ]
    if not ai_nodes:
        ai_nodes = list(all_names)

    ai_region_names = [
        r_name for r_name in active_region_names if "香港" not in r_name
    ]

    groups: List[Dict[str, Any]] = [
        {
            "name": "🚀 节点选择",
            "type": "select",
            "proxies": ["♻️ 自动选择", "🛡️ 故障转移"] + active_region_names + all_names + ["DIRECT"],
        },
        {
            "name": "♻️ 自动选择",
            "type": "url-test",
            "url": test_url,
            "interval": test_interval,
            "tolerance": test_tolerance,
            "lazy": True,
            "proxies": list(all_names),
        },
        {
            "name": "🛡️ 故障转移",
            "type": "fallback",
            "url": test_url,
            "interval": 180,
            "lazy": True,
            "proxies": list(all_names),
        },
        {
            "name": "🤖 AI 专线",
            "type": "select",
            "proxies": ["⚡ AI 自动优选"] + ai_region_names + ai_nodes,
        },
        {
            "name": "⚡ AI 自动优选",
            "type": "url-test",
            "url": test_url,
            "interval": test_interval,
            "tolerance": test_tolerance,
            "lazy": True,
            "proxies": ai_nodes,
        },
        {
            "name": "📹 YouTube",
            "type": "select",
            "proxies": ["🚀 节点选择", "♻️ 自动选择", "🛡️ 故障转移"] + active_region_names + all_names,
        },
        {
            "name": "📲 Telegram",
            "type": "select",
            "proxies": ["🚀 节点选择", "♻️ 自动选择", "🛡️ 故障转移"] + active_region_names + all_names,
        },
        {
            "name": "🎬 流媒体服务",
            "type": "select",
            "proxies": ["🚀 节点选择", "♻️ 自动选择"] + active_region_names + all_names,
        },
        {
            "name": "🍎 苹果与微软",
            "type": "select",
            "proxies": ["DIRECT", "🚀 节点选择", "♻️ 自动选择"],
        },
        {
            "name": "🎯 全球直连",
            "type": "select",
            "proxies": ["DIRECT", "🚀 节点选择"],
        },
        {
            "name": "🛑 广告拦截",
            "type": "select",
            "proxies": ["REJECT", "DIRECT"],
        },
        {
            "name": "🐟 漏网之鱼",
            "type": "select",
            "proxies": ["🚀 节点选择", "♻️ 自动选择", "🛡️ 故障转移", "DIRECT"],
        },
    ]

    # 自定义分流组：插在核心组之后、地区组之前；与内置组重名则丢弃
    core_names = {g["name"] for g in groups}
    groups.extend(
        g
        for g in build_custom_groups(proxies, settings, custom_groups)
        if g["name"] not in core_names
    )

    groups.extend(active_region_groups)
    return groups


def generate_subscription_output(store: Dict[str, Any], target: str = "mihomo") -> str:
    if target == "singbox":
        # 懒加载：app.singbox 反向依赖本模块的 collect_all_proxies
        from app.singbox import generate_singbox_config

        return generate_singbox_config(store)

    proxies, raw_uris = collect_all_proxies(store)
    settings = store.get("settings", {})

    if target == "base64":
        # 全部有效节点（含自建与远程订阅）都带最终修饰名输出，不再是原始 raw_uris
        uris = [u for u in (proxy_dict_to_share_uri(p) for p in proxies) if u]
        return base64.b64encode("\n".join(uris).encode("utf-8")).decode("utf-8")

    # fingerprint / _raw_uri 是内部元数据，不输出到订阅里
    clean_proxies = [
        {k: v for k, v in p.items() if k not in ("fingerprint", "_raw_uri")}
        for p in proxies
    ]

    if target == "proxies":
        return yaml.safe_dump(
            {"proxies": clean_proxies}, allow_unicode=True, sort_keys=False
        )

    base_text = load_template()
    base_cfg = yaml.safe_load(base_text) or {}

    rules = base_cfg.pop("rules", [])
    rule_providers = base_cfg.pop("rule-providers", {})

    base_cfg["proxies"] = clean_proxies
    proxy_groups = build_proxy_groups(
        proxies, settings, store.get("custom_groups", [])
    )
    base_cfg["proxy-groups"] = proxy_groups
    if rule_providers:
        base_cfg["rule-providers"] = rule_providers
    # 自定义分流规则插到最前面，优先级高于模板内置规则
    custom_rules = _build_custom_mihomo_rules(
        store.get("custom_rules", []), {g["name"] for g in proxy_groups}
    )
    if custom_rules or rules:
        base_cfg["rules"] = custom_rules + rules

    return yaml.safe_dump(base_cfg, allow_unicode=True, sort_keys=False, width=1000)
