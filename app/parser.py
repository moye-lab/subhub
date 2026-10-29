import re
import json
import base64
import yaml
from typing import List, Dict, Any, Optional
from urllib.parse import urlsplit, parse_qs, unquote

from app.fingerprint import compute_fingerprint

EMOJI_RULES = [
    (r"(?i)(hk|hong\s*kong|香港|深港|沪港)", "🇭🇰"),
    (r"(?i)(tw|taiwan|台湾|台北|新北|彰化)", "🇹🇼"),
    (r"(?i)(jp|japan|日本|东京|大阪|埼玉|软银|IIJ)", "🇯🇵"),
    (r"(?i)(sg|singapore|新加坡|狮城)", "🇸🇬"),
    (r"(?i)(us|usa|america|united\s*states|美国|洛杉矶|圣何塞|西雅图|硅谷|芝加哥|纽约|凤凰城|弗里蒙特)", "🇺🇸"),
    (r"(?i)(kr|korea|韩国|首尔|釜山)", "🇰🇷"),
    (r"(?i)(de|germany|德国|法兰克福)", "🇩🇪"),
    (r"(?i)(gb|uk|united\s*kingdom|英国|伦敦)", "🇬🇧"),
    (r"(?i)(fr|france|法国|巴黎)", "🇫🇷"),
    (r"(?i)(nl|netherlands|荷兰|阿姆斯特丹)", "🇳🇱"),
    (r"(?i)(ca|canada|加拿大|温哥华|多伦多)", "🇨🇦"),
    (r"(?i)(au|australia|澳大利亚|悉尼|墨尔本)", "🇦🇺"),
    (r"(?i)(ru|russia|俄罗斯|莫斯科)", "🇷🇺"),
]


def safe_b64decode(s: str) -> str:
    s = s.strip().replace("\n", "").replace("\r", "").replace(" ", "")
    s = s.replace("-", "+").replace("_", "/")
    pad = len(s) % 4
    if pad:
        s += "=" * (4 - pad)
    return base64.b64decode(s).decode("utf-8", errors="ignore")


def decorate_name(
    raw_name: str,
    vps_tag: str = "",
    custom_name: str = "",
    auto_emoji: bool = True,
    prepend_vps_tag: bool = True,
) -> str:
    name = (custom_name or raw_name or "Unnamed").strip()
    if prepend_vps_tag and vps_tag and vps_tag not in name:
        name = f"[{vps_tag}] {name}"

    if auto_emoji:
        has_flag = any(flag in name for _, flag in EMOJI_RULES) or "🌐" in name
        if not has_flag:
            matched_flag = "🌐"
            for pattern, flag in EMOJI_RULES:
                if re.search(pattern, name):
                    matched_flag = flag
                    break
            name = f"{matched_flag} {name}"
    return name


def _first(q: Dict[str, List[str]], key: str, default: str = "") -> str:
    vals = q.get(key)
    return unquote(vals[0]) if vals else default


def _parse_host_port(netloc: str):
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)
    else:
        userinfo, hostport = "", netloc
    userinfo = unquote(userinfo)

    if hostport.startswith("["):
        # IPv6
        end_bracket = hostport.find("]")
        host = hostport[1:end_bracket]
        port_part = hostport[end_bracket + 1 :]
        port = int(port_part.lstrip(":")) if port_part.startswith(":") else 443
    else:
        if ":" in hostport:
            host, port_str = hostport.rsplit(":", 1)
            port = int(port_str)
        else:
            host, port = hostport, 443
    return userinfo, host, port


def parse_vless(uri: str, udp_default: bool = True) -> Optional[Dict[str, Any]]:
    sp = urlsplit(uri)
    uuid, server, port = _parse_host_port(sp.netloc)
    if not uuid or not server:
        return None
    q = parse_qs(sp.query)
    name = unquote(sp.fragment) or f"VLESS-{server}:{port}"
    network = _first(q, "type", "tcp")
    security = _first(q, "security", "none")

    proxy: Dict[str, Any] = {
        "name": name,
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": uuid,
        "udp": udp_default,
        "tls": security in ("tls", "reality"),
        "network": network,
    }

    flow = _first(q, "flow")
    if flow:
        proxy["flow"] = flow

    sni = _first(q, "sni") or _first(q, "peer")
    if sni:
        proxy["servername"] = sni

    fp = _first(q, "fp", "chrome")
    if proxy["tls"] and fp:
        proxy["client-fingerprint"] = fp

    alpn = _first(q, "alpn")
    if alpn:
        proxy["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]

    insecure = _first(q, "allowInsecure") or _first(q, "insecure")
    if insecure in ("1", "true", "True"):
        proxy["skip-cert-verify"] = True

    if security == "reality":
        pbk = _first(q, "pbk")
        sid = _first(q, "sid")
        reality_opts: Dict[str, Any] = {"public-key": pbk}
        if sid:
            reality_opts["short-id"] = sid
        proxy["reality-opts"] = reality_opts

    if network == "ws":
        ws_opts: Dict[str, Any] = {"path": _first(q, "path", "/")}
        host = _first(q, "host")
        if host:
            ws_opts["headers"] = {"Host": host}
        proxy["ws-opts"] = ws_opts
    elif network == "grpc":
        sn = _first(q, "serviceName") or _first(q, "path")
        if sn:
            proxy["grpc-opts"] = {"grpc-service-name": sn}

    return proxy


def parse_hysteria2(uri: str, udp_default: bool = True) -> Optional[Dict[str, Any]]:
    norm_uri = "hysteria2://" + uri.split("://", 1)[1]
    sp = urlsplit(norm_uri)
    password, server, port = _parse_host_port(sp.netloc)
    if not server:
        return None
    q = parse_qs(sp.query)
    name = unquote(sp.fragment) or f"Hy2-{server}:{port}"

    proxy: Dict[str, Any] = {
        "name": name,
        "type": "hysteria2",
        "server": server,
        "port": port,
        "password": password,
        "udp": True,
    }

    sni = _first(q, "sni") or _first(q, "peer")
    if sni:
        proxy["sni"] = sni

    insecure = _first(q, "insecure") or _first(q, "allowInsecure")
    if insecure in ("1", "true", "True"):
        proxy["skip-cert-verify"] = True

    obfs = _first(q, "obfs")
    if obfs and obfs != "none":
        proxy["obfs"] = obfs
        obfs_pw = _first(q, "obfs-password")
        if obfs_pw:
            proxy["obfs-password"] = obfs_pw

    mport = _first(q, "mport")
    if mport:
        proxy["ports"] = mport

    return proxy


def parse_tuic(uri: str, udp_default: bool = True) -> Optional[Dict[str, Any]]:
    sp = urlsplit(uri)
    userinfo, server, port = _parse_host_port(sp.netloc)
    if ":" in userinfo:
        uuid, password = userinfo.split(":", 1)
    else:
        uuid, password = userinfo, ""
    q = parse_qs(sp.query)
    name = unquote(sp.fragment) or f"TUIC-{server}:{port}"

    proxy: Dict[str, Any] = {
        "name": name,
        "type": "tuic",
        "server": server,
        "port": port,
        "uuid": uuid,
        "password": password,
        "udp": True,
        "congestion-controller": _first(q, "congestion_control", "bbr"),
        "udp-relay-mode": _first(q, "udp_relay_mode", "native"),
    }

    sni = _first(q, "sni")
    if sni:
        proxy["sni"] = sni

    alpn = _first(q, "alpn")
    if alpn:
        proxy["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]

    insecure = _first(q, "allow_insecure") or _first(q, "insecure") or _first(q, "allowInsecure")
    if insecure in ("1", "true", "True"):
        proxy["skip-cert-verify"] = True

    return proxy


def parse_trojan(uri: str, udp_default: bool = True) -> Optional[Dict[str, Any]]:
    sp = urlsplit(uri)
    password, server, port = _parse_host_port(sp.netloc)
    if not server:
        return None
    q = parse_qs(sp.query)
    name = unquote(sp.fragment) or f"Trojan-{server}:{port}"
    network = _first(q, "type", "tcp")

    proxy: Dict[str, Any] = {
        "name": name,
        "type": "trojan",
        "server": server,
        "port": port,
        "password": password,
        "udp": udp_default,
        "network": network,
    }

    sni = _first(q, "sni") or _first(q, "peer")
    if sni:
        proxy["sni"] = sni

    fp = _first(q, "fp", "chrome")
    if fp:
        proxy["client-fingerprint"] = fp

    insecure = _first(q, "allowInsecure") or _first(q, "insecure")
    if insecure in ("1", "true", "True"):
        proxy["skip-cert-verify"] = True

    if network == "ws":
        ws_opts: Dict[str, Any] = {"path": _first(q, "path", "/")}
        host = _first(q, "host")
        if host:
            ws_opts["headers"] = {"Host": host}
        proxy["ws-opts"] = ws_opts
    elif network == "grpc":
        sn = _first(q, "serviceName")
        if sn:
            proxy["grpc-opts"] = {"grpc-service-name": sn}

    return proxy


def parse_ss(uri: str, udp_default: bool = True) -> Optional[Dict[str, Any]]:
    raw = uri[5:]
    if "#" in raw:
        body, frag = raw.split("#", 1)
        name = unquote(frag)
    else:
        body, name = raw, ""

    if "?" in body:
        body, _ = body.split("?", 1)

    if "@" in body:
        b64_user, hostport = body.rsplit("@", 1)
        b64_user = unquote(b64_user)
        if ":" in b64_user and not b64_user.endswith("="):
            decoded_user = b64_user
        else:
            decoded_user = safe_b64decode(b64_user)
        _, server, port = _parse_host_port(hostport)
    else:
        decoded_full = safe_b64decode(body)
        decoded_user, server, port = _parse_host_port(decoded_full)

    if ":" not in decoded_user or not server:
        return None

    cipher, password = decoded_user.split(":", 1)
    return {
        "name": name or f"SS-{server}:{port}",
        "type": "ss",
        "server": server,
        "port": port,
        "cipher": cipher,
        "password": password,
        "udp": udp_default,
    }


def parse_vmess(uri: str, udp_default: bool = True) -> Optional[Dict[str, Any]]:
    b64_part = uri[8:].strip()
    data = json.loads(safe_b64decode(b64_part))
    server = data.get("add")
    port = int(data.get("port", 443))
    uuid = data.get("id")
    if not server or not uuid:
        return None

    net = data.get("net", "tcp")
    tls_val = str(data.get("tls", "")).lower()
    is_tls = tls_val in ("tls", "true", "1")

    proxy: Dict[str, Any] = {
        "name": data.get("ps") or f"VMess-{server}:{port}",
        "type": "vmess",
        "server": server,
        "port": port,
        "uuid": uuid,
        "alterId": int(data.get("aid", 0)),
        "cipher": data.get("scy", "auto") or "auto",
        "udp": udp_default,
        "tls": is_tls,
        "network": net,
    }

    sni = data.get("sni") or data.get("host")
    if is_tls and sni:
        proxy["servername"] = sni

    if net == "ws":
        ws_opts: Dict[str, Any] = {"path": data.get("path") or "/"}
        if data.get("host"):
            ws_opts["headers"] = {"Host": data["host"]}
        proxy["ws-opts"] = ws_opts
    elif net == "grpc":
        if data.get("path"):
            proxy["grpc-opts"] = {"grpc-service-name": data["path"]}

    return proxy


def parse_socks5(uri: str, udp_default: bool = True) -> Optional[Dict[str, Any]]:
    sp = urlsplit(uri)
    userinfo, server, port = _parse_host_port(sp.netloc)
    name = unquote(sp.fragment) or f"Socks5-{server}:{port}"
    proxy: Dict[str, Any] = {
        "name": name,
        "type": "socks5",
        "server": server,
        "port": port,
        "udp": udp_default,
    }
    if userinfo:
        if ":" not in userinfo:
            userinfo = safe_b64decode(userinfo)
        if ":" in userinfo:
            user, pw = userinfo.split(":", 1)
            proxy["username"] = user
            proxy["password"] = pw
    return proxy


def parse_single_line(
    line: str,
    vps_tag: str = "",
    custom_name: str = "",
    auto_emoji: bool = True,
    prepend_vps_tag: bool = True,
    udp_default: bool = True,
) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    proxy: Optional[Dict[str, Any]] = None
    try:
        lower = line.lower()
        if lower.startswith("vless://"):
            proxy = parse_vless(line, udp_default)
        elif lower.startswith(("hysteria2://", "hy2://")):
            proxy = parse_hysteria2(line, udp_default)
        elif lower.startswith("tuic://"):
            proxy = parse_tuic(line, udp_default)
        elif lower.startswith("trojan://"):
            proxy = parse_trojan(line, udp_default)
        elif lower.startswith("ss://"):
            proxy = parse_ss(line, udp_default)
        elif lower.startswith("vmess://"):
            proxy = parse_vmess(line, udp_default)
        elif lower.startswith(("socks5://", "socks://")):
            proxy = parse_socks5(line, udp_default)
        elif line.startswith("- {") or line.startswith("{") or "type:" in line:
            loaded = yaml.safe_load(line)
            if isinstance(loaded, list) and loaded and isinstance(loaded[0], dict):
                proxy = loaded[0]
            elif isinstance(loaded, dict):
                proxy = loaded
    except Exception:
        return None

    if proxy and isinstance(proxy, dict) and "server" in proxy and "type" in proxy:
        proxy["name"] = decorate_name(
            raw_name=str(proxy.get("name", "")),
            vps_tag=vps_tag,
            custom_name=custom_name,
            auto_emoji=auto_emoji,
            prepend_vps_tag=prepend_vps_tag,
        )
        # 指纹与显示名无关：同一条线路换备注名，指纹不变
        proxy["fingerprint"] = compute_fingerprint(proxy)
        return proxy
    return None
