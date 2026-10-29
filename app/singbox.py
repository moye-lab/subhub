"""sing-box JSON 订阅输出。

把解析后的节点（Clash 风格字段）转换为 sing-box 原生 JSON 配置，
供 sing-box 官方客户端通过订阅地址或 `sing-box://import-remote-profile`
一键导入。
"""
import json
from typing import Dict, Any, List, Optional, Set

from app.config import TEMPLATE_FILE
from app.generator import collect_all_proxies, build_proxy_groups

SELECTOR_TAG = "🚀 节点选择"
AI_GROUP_TAG = "🤖 AI 专线"


def _int_port(p: Dict[str, Any]) -> int:
    try:
        return int(p.get("port", 0))
    except (TypeError, ValueError):
        return 0


def _tls_block(p: Dict[str, Any]) -> Dict[str, Any]:
    tls: Dict[str, Any] = {"enabled": True}
    server_name = p.get("servername") or p.get("sni")
    if server_name:
        tls["server_name"] = server_name
    if p.get("skip-cert-verify"):
        tls["insecure"] = True
    fp = p.get("client-fingerprint")
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    alpn = p.get("alpn")
    if alpn:
        tls["alpn"] = list(alpn)
    return tls


def _transport_block(p: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    net = str(p.get("network") or "tcp").lower()
    if net == "ws":
        ws = p.get("ws-opts") or {}
        t: Dict[str, Any] = {"type": "ws", "path": ws.get("path") or "/"}
        headers = ws.get("headers")
        if headers:
            t["headers"] = dict(headers)
        return t
    if net == "grpc":
        g = p.get("grpc-opts") or {}
        t = {"type": "grpc"}
        service_name = g.get("grpc-service-name")
        if service_name:
            t["service_name"] = service_name
        return t
    return None


def _convert_shadowsocks(p: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "type": "shadowsocks",
        "tag": p["name"],
        "server": p["server"],
        "server_port": _int_port(p),
        "method": p.get("cipher") or "aes-256-gcm",
        "password": p.get("password", ""),
    }


def _convert_vmess(p: Dict[str, Any]) -> Dict[str, Any]:
    cipher = str(p.get("cipher", "auto") or "auto").lower()
    security = {
        "auto": "auto",
        "aes-128-gcm": "aes-128-gcm",
        "chacha20-poly1305": "chacha20-poly1305",
        "none": "none",
    }.get(cipher, "auto")
    try:
        alter_id = int(p.get("alterId", 0) or 0)
    except (TypeError, ValueError):
        alter_id = 0
    ob: Dict[str, Any] = {
        "type": "vmess",
        "tag": p["name"],
        "server": p["server"],
        "server_port": _int_port(p),
        "uuid": p.get("uuid", ""),
        "security": security,
        "alter_id": alter_id,
    }
    if p.get("tls"):
        ob["tls"] = _tls_block(p)
    transport = _transport_block(p)
    if transport:
        ob["transport"] = transport
    return ob


def _convert_vless(p: Dict[str, Any]) -> Dict[str, Any]:
    ob: Dict[str, Any] = {
        "type": "vless",
        "tag": p["name"],
        "server": p["server"],
        "server_port": _int_port(p),
        "uuid": p.get("uuid", ""),
    }
    flow = p.get("flow")
    if flow:
        ob["flow"] = flow
    if p.get("tls"):
        tls = _tls_block(p)
        reality_opts = p.get("reality-opts") or {}
        public_key = reality_opts.get("public-key")
        if public_key:
            reality: Dict[str, Any] = {"enabled": True, "public_key": public_key}
            short_id = reality_opts.get("short-id")
            if short_id:
                reality["short_id"] = short_id
            tls["reality"] = reality
        ob["tls"] = tls
    transport = _transport_block(p)
    if transport:
        ob["transport"] = transport
    return ob


def _convert_trojan(p: Dict[str, Any]) -> Dict[str, Any]:
    ob: Dict[str, Any] = {
        "type": "trojan",
        "tag": p["name"],
        "server": p["server"],
        "server_port": _int_port(p),
        "password": p.get("password", ""),
        # trojan 恒走 TLS
        "tls": _tls_block(p),
    }
    transport = _transport_block(p)
    if transport:
        ob["transport"] = transport
    return ob


def _convert_hysteria2(p: Dict[str, Any]) -> Dict[str, Any]:
    ob: Dict[str, Any] = {
        "type": "hysteria2",
        "tag": p["name"],
        "server": p["server"],
        "server_port": _int_port(p),
        "password": p.get("password", ""),
        "tls": _tls_block(p),
    }
    obfs = p.get("obfs")
    if obfs and str(obfs).lower() != "none":
        obfs_block: Dict[str, Any] = {"type": str(obfs)}
        obfs_password = p.get("obfs-password")
        if obfs_password:
            obfs_block["password"] = obfs_password
        ob["obfs"] = obfs_block
    return ob


def _convert_tuic(p: Dict[str, Any]) -> Dict[str, Any]:
    ob: Dict[str, Any] = {
        "type": "tuic",
        "tag": p["name"],
        "server": p["server"],
        "server_port": _int_port(p),
        "uuid": p.get("uuid", ""),
        "password": p.get("password", ""),
        "tls": _tls_block(p),
    }
    congestion = p.get("congestion-controller")
    if congestion:
        ob["congestion_control"] = congestion
    relay_mode = p.get("udp-relay-mode")
    if relay_mode in ("native", "quic"):
        ob["udp_relay_mode"] = relay_mode
    return ob


def _convert_socks(p: Dict[str, Any]) -> Dict[str, Any]:
    ob: Dict[str, Any] = {
        "type": "socks",
        "tag": p["name"],
        "server": p["server"],
        "server_port": _int_port(p),
        "version": "5",
    }
    if p.get("username"):
        ob["username"] = p["username"]
    if p.get("password"):
        ob["password"] = p["password"]
    return ob


_CONVERTERS = {
    "ss": _convert_shadowsocks,
    "shadowsocks": _convert_shadowsocks,
    "vmess": _convert_vmess,
    "vless": _convert_vless,
    "trojan": _convert_trojan,
    "hysteria2": _convert_hysteria2,
    "hy2": _convert_hysteria2,
    "tuic": _convert_tuic,
    "socks": _convert_socks,
    "socks5": _convert_socks,
}


def convert_proxy(p: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """单个节点转 sing-box outbound；不支持的协议返回 None（跳过，不中断）。"""
    converter = _CONVERTERS.get(str(p.get("type", "")).lower())
    if not converter:
        return None
    try:
        outbound = converter(p)
    except Exception:
        return None
    if not outbound.get("server") or not outbound.get("server_port"):
        return None
    return outbound


def _load_ai_domains() -> List[str]:
    """从底座模板的 rules 里提取指向 🤖 AI 专线的 DOMAIN-SUFFIX，
    转 sing-box domain_suffix 路由规则，与用户可编辑的模板保持同步。"""
    domains: List[str] = []
    try:
        text = TEMPLATE_FILE.read_text(encoding="utf-8")
    except OSError:
        return domains
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("- DOMAIN-SUFFIX,"):
            continue
        parts = [p.strip() for p in line[1:].strip().split(",")]
        if len(parts) >= 3 and parts[0] == "DOMAIN-SUFFIX" and parts[2] == AI_GROUP_TAG:
            domains.append(parts[1])
    # 去重保序
    return list(dict.fromkeys(domains))


def _convert_groups(
    proxies: List[Dict[str, Any]],
    settings: Dict[str, Any],
    names: List[str],
    node_tags: Set[str],
    custom_groups: List[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """把 build_proxy_groups（与 Mihomo 输出同一套分组）转成 sing-box 出站。

    - select → selector（成员可嵌套引用其它组）
    - url-test → urltest（只保留真实节点成员，嵌套组引用无测速意义）
    - fallback → selector：sing-box 无原生 fallback 类型，转手动选择，
      tag 名不变，其它组的引用不断
    - DIRECT → direct，REJECT → block；未知引用丢弃，防悬空
    - 自定义分流组随 build_proxy_groups 一并转换
    """
    mihomo_groups = build_proxy_groups(proxies, settings, custom_groups)
    group_names = {g["name"] for g in mihomo_groups}

    def map_member(m: str) -> Optional[str]:
        if m == "DIRECT":
            return "direct"
        if m == "REJECT":
            return "block"
        if m in node_tags or m in group_names:
            return m
        return None

    # 第一遍：算出每个组映射后的成员，确定 urltest 能否发射
    # （无节点成员的 urltest 无意义，跳过，避免悬空引用）
    planned: List[Dict[str, Any]] = []
    for g in mihomo_groups:
        members: List[str] = []
        for m in g.get("proxies", []):
            tag = map_member(m)
            if tag and tag not in members:
                members.append(tag)
        planned.append({"name": g["name"], "type": g.get("type", "select"),
                        "members": members, "group": g})

    emitted = {p["name"] for p in planned
               if not (p["type"] == "url-test"
                       and not [m for m in p["members"] if m in node_tags])}
    emitted |= node_tags | {"direct", "block"}

    outbounds: List[Dict[str, Any]] = []
    for p in planned:
        name, gtype, members = p["name"], p["type"], p["members"]
        members = [m for m in members if m in emitted]
        if gtype == "url-test":
            node_members = [m for m in members if m in node_tags]
            if not node_members:
                continue
            g = p["group"]
            outbounds.append({
                "type": "urltest",
                "tag": name,
                "outbounds": node_members,
                "url": g.get("url") or settings.get(
                    "test_url", "https://www.gstatic.com/generate_204"),
                "interval": f"{int(g.get('interval', 300))}s",
                "tolerance": int(g.get("tolerance", 50)),
            })
        else:
            if not members:
                members = ["direct"]
            ob: Dict[str, Any] = {
                "type": "selector",
                "tag": name,
                "outbounds": members,
            }
            if name == SELECTOR_TAG:
                ob["default"] = names[0] if names else "direct"
            outbounds.append(ob)
    return outbounds


def _build_custom_route_rules(
    custom_rules: List[Dict[str, Any]], emitted_tags: Set[str]
) -> List[Dict[str, Any]]:
    """自定义分流规则转 sing-box route.rules。目标不存在时回退主选择组。"""
    key_map = {
        "DOMAIN-SUFFIX": "domain_suffix",
        "DOMAIN-KEYWORD": "domain_keyword",
        "DOMAIN": "domain",
        "IP-CIDR": "ip_cidr",
        "PROCESS-NAME": "process_name",
    }
    out: List[Dict[str, Any]] = []
    for r in custom_rules or []:
        if not r.get("enabled", True):
            continue
        value = (r.get("value") or "").strip()
        if not value:
            continue
        key = key_map.get((r.get("rule_type") or "DOMAIN-SUFFIX").strip().upper())
        if not key:
            continue
        target = (r.get("target") or "").strip()
        if target == "DIRECT":
            outbound = "direct"
        elif target == "REJECT":
            outbound = "block"
        elif target in emitted_tags:
            outbound = target
        else:
            outbound = SELECTOR_TAG
        out.append({key: [value], "outbound": outbound})
    return out


def generate_singbox_config(store: Dict[str, Any]) -> str:
    """生成完整的 sing-box JSON 配置。

    分组与 Mihomo 输出同一套（地区组 / AI 专线 / YouTube / Telegram /
    流媒体 / 苹果与微软 / 全球直连 / 广告拦截 / 漏网之鱼），DNS 与路由
    写法对齐 sg/sub-panel 的 iOS 实测可用版本。
    """
    proxies, _ = collect_all_proxies(store)
    settings = store.get("settings", {})

    outbounds: List[Dict[str, Any]] = []
    names: List[str] = []
    for p in proxies:
        outbound = convert_proxy(p)
        if outbound:
            outbounds.append(outbound)
            names.append(outbound["tag"])
    node_tags = set(names)

    outbounds.extend(
        _convert_groups(
            proxies, settings, names, node_tags, store.get("custom_groups", [])
        )
    )
    emitted_tags = {o["tag"] for o in outbounds}

    # AI 域名分流：模板里指向 🤖 AI 专线的域名自动走 AI 组
    route_rules: List[Dict[str, Any]] = [
        {"protocol": "dns", "action": "hijack-dns"},
        {"action": "sniff"},
    ]
    # 自定义分流规则：插在 sniff 之后，优先级高于 AI 域名与内置规则
    route_rules.extend(
        _build_custom_route_rules(store.get("custom_rules", []), emitted_tags)
    )
    ai_domains = _load_ai_domains()
    if ai_domains and AI_GROUP_TAG in emitted_tags:
        route_rules.append({"domain_suffix": ai_domains, "outbound": AI_GROUP_TAG})

    outbounds.extend(
        [
            # direct 带 domain_resolver：一是让它成为"非空"出站（1.14+ 拒绝
            # detour 到空 direct 出站）；二是直连流量的域名解析走直连 DNS，不泄漏
            {"type": "direct", "tag": "direct",
             "domain_resolver": {"server": "direct-dns"}},
            {"type": "block", "tag": "block"},
            # 注意：1.13+ 已移除 dns 出站，DNS 查询改走路由 hijack-dns 动作，
            # 这里不再声明 dns-out
        ]
    )

    config = {
        "log": {"level": "info", "timestamp": True},
        # 防 DNS 泄漏：所有 DNS 查询被 route 以 hijack-dns 劫持，由 sing-box 的
        # DNS 客户端处理；国内域名走直连 DoH（223.5.5.5），其余走代理 DoH。
        # （写法对齐 sg/sub-panel 的 to_singbox_json，iOS 实测可用）
        "dns": {
            "servers": [
                {
                    "tag": "proxy-dns",
                    "type": "https",
                    "server": "1.1.1.1",
                    "detour": SELECTOR_TAG,
                },
                # direct-dns 不写 detour：无 detour 即直连；写 detour 到空 direct
                # 出站在 1.14+ 启动时会被拒绝（detour to an empty direct outbound）
                {"tag": "direct-dns", "type": "https", "server": "223.5.5.5"},
            ],
            "rules": [
                {"rule_set": ["geosite-cn"], "action": "route", "server": "direct-dns"},
                {"action": "route", "server": "proxy-dns"},
            ],
            "final": "proxy-dns",
            "strategy": "prefer_ipv4",
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                # 1.10 起 inet4_address/inet6_address 合并为 address
                "address": ["172.19.0.1/30"],
                "auto_route": True,
                "strict_route": True,
                # 不写 stack：sing-box 1.15 起 stack 选项已弃用、1.17 移除，
                # 缺省即用新版 sing-tun 自研栈
                # 不写 sniff：入站级 sniff 等字段 1.11 弃用、1.13 移除，
                # 已迁为下方 route.rules 首条 {"action": "sniff"}
            },
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2080,
            },
        ],
        "outbounds": outbounds,
        "route": {
            "rules": route_rules
            + [
                {"ip_is_private": True, "outbound": "direct"},
                {"rule_set": ["geosite-cn", "geoip-cn"], "outbound": "direct"},
            ],
            "rule_set": [
                {
                    "tag": "geosite-cn",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
                    "download_detour": SELECTOR_TAG,
                },
                {
                    "tag": "geoip-cn",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
                    "download_detour": SELECTOR_TAG,
                },
            ],
            "final": SELECTOR_TAG,
            "auto_detect_interface": True,
            # 出站拨号时解析域名（如节点域名、规则集下载地址）用的 DNS
            "default_domain_resolver": {"server": "direct-dns"},
        },
        "experimental": {"cache_file": {"enabled": True}},
    }
    return json.dumps(config, ensure_ascii=False, indent=2)
