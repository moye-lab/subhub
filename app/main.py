import uuid
import json
import re
import time
import asyncio
import hashlib
import hmac
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote
from fastapi import FastAPI, HTTPException, Header, Query, Depends, Request
from fastapi.responses import HTMLResponse, Response
from app.config import ADMIN_PASSWORD
from app.models import (
    LoginRequest,
    SettingsUpdate,
    NodeBatchCreate,
    NodeUpdate,
    BatchToggleRequest,
    SubCreate,
    SubUpdate,
    TemplateUpdate,
    PasswordChangeRequest,
    PingRequest,
    BackupImportRequest,
    CustomGroupCreate,
    CustomGroupUpdate,
    CustomRuleCreate,
    CustomRuleUpdate,
    NodeBatchDeleteRequest,
)
from app.storage import load_store, save_store, load_template, save_template
from app.parser import parse_single_line
from app.fetcher import fetch_single_subscription
from app.generator import (
    generate_subscription_output,
    collect_all_proxies,
    build_proxy_groups,
)


async def _auto_refresh_loop() -> None:
    """后台定时刷新启用的远程订阅源。异常只记不抛，不中断主服务。"""
    while True:
        try:
            store = await load_store()
            interval = store.get("settings", {}).get("sub_refresh_interval", 21600)
            interval = int(interval or 21600)
            if interval < 600:
                interval = 600
        except Exception:
            interval = 21600
        await asyncio.sleep(interval)
        try:
            store = await load_store()
            settings = store.get("settings", {})
            for sub in store.get("subscriptions", []):
                if sub.get("enabled", True):
                    try:
                        await fetch_single_subscription(sub, settings)
                    except Exception:
                        continue
            await save_store(store)
        except Exception:
            continue


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(_auto_refresh_loop())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="SubHub - 个人多 VPS 节点订阅管理系统",
    version="1.0.0",
    lifespan=lifespan,
)

STATIC_INDEX = Path(__file__).resolve().parent / "static" / "index.html"


def _hash_password(pw: str) -> str:
    return hashlib.sha256((pw or "").encode("utf-8")).hexdigest()


def _check_password(input_pw: str, settings: dict) -> bool:
    """校验管理密码。优先级：设置页修改过的密码(hash) > 环境变量 > 默认值。"""
    stored_hash = (settings.get("admin_password_hash") or "").strip()
    if stored_hash:
        return hmac.compare_digest(_hash_password(input_pw), stored_hash)
    return hmac.compare_digest(input_pw or "", ADMIN_PASSWORD)


async def verify_admin(x_admin_token: str = Header(default="")):
    store = await load_store()
    if not _check_password(x_admin_token, store.get("settings", {})):
        raise HTTPException(status_code=401, detail="管理员密码错误或未授权")


@app.get("/", response_class=HTMLResponse)
async def index_page():
    return STATIC_INDEX.read_text(encoding="utf-8")


# 登录防爆破：ip -> [连续失败次数, 首次失败时间戳, 锁定到期时间戳]
_login_attempts: Dict[str, list] = {}
_LOGIN_FAIL_WINDOW = 300  # 5 分钟滑动窗口
_LOGIN_MAX_FAILS = 5  # 窗口内连续失败 5 次则锁定
_LOGIN_LOCK_SECONDS = 900  # 锁定 15 分钟


def _login_allowed(ip: str) -> bool:
    now = time.time()
    rec = _login_attempts.get(ip)
    if not rec:
        return True
    fails, first_ts, locked_until = rec
    if locked_until and now < locked_until:
        return False
    # 锁定到期或窗口过期：清零
    if (locked_until and now >= locked_until) or (now - first_ts > _LOGIN_FAIL_WINDOW):
        _login_attempts.pop(ip, None)
    return True


def _record_login_fail(ip: str) -> None:
    now = time.time()
    rec = _login_attempts.get(ip)
    if not rec or now - rec[1] > _LOGIN_FAIL_WINDOW:
        _login_attempts[ip] = [1, now, 0]
    else:
        rec[0] += 1
        if rec[0] >= _LOGIN_MAX_FAILS:
            rec[2] = now + _LOGIN_LOCK_SECONDS


def _record_login_success(ip: str) -> None:
    _login_attempts.pop(ip, None)


@app.get("/api/health")
async def health_check():
    from app import __version__
    return {"status": "ok", "version": __version__}


@app.post("/api/login")
async def login(req: LoginRequest, request: Request):
    ip = request.client.host if request.client else "unknown"
    if not _login_allowed(ip):
        raise HTTPException(
            status_code=429, detail="密码错误次数过多，请 15 分钟后再试"
        )
    store = await load_store()
    if not _check_password(req.password, store.get("settings", {})):
        _record_login_fail(ip)
        raise HTTPException(status_code=401, detail="密码错误")
    _record_login_success(ip)
    # token 即用户输入的密码原文；后续请求用它做哈希比对
    return {"ok": True, "token": req.password}


def _detect_target_from_ua(user_agent: str) -> str:
    """根据客户端 User-Agent 猜订阅格式；兜底 mihomo。"""
    ua = (user_agent or "").lower()
    if any(k in ua for k in ("sing-box", "sfa", "sfm", "sfi", "sft")):
        return "singbox"
    if any(
        k in ua
        for k in ("shadowrocket", "v2rayn", "nekobox", "v2rayng", "quantumult")
    ):
        return "base64"
    return "mihomo"


@app.get("/sub/{sub_token}")
async def get_subscription(
    sub_token: str,
    target: str = Query(
        default="auto",
        pattern="^(auto|mihomo|clash|singbox|sing-box|proxies|base64)$",
    ),
    user_agent: str = Header(default="", alias="User-Agent"),
):
    store = await load_store()
    expected_token = store.get("settings", {}).get("sub_token", "")
    if not expected_token or sub_token != expected_token:
        raise HTTPException(status_code=403, detail="无效的订阅 Token")

    # Auto refresh enabled subscriptions if cache is empty
    for sub in store.get("subscriptions", []):
        if sub.get("enabled", True) and not sub.get("cached_proxies"):
            await fetch_single_subscription(sub, store.get("settings", {}))
    await save_store(store)

    t = target
    if t == "auto":
        t = _detect_target_from_ua(user_agent)
    elif t == "clash":
        t = "mihomo"
    elif t == "sing-box":
        t = "singbox"

    output = generate_subscription_output(store, target=t)
    filename = store.get("settings", {}).get("sub_filename", "SubHub")
    ext = "json" if t == "singbox" else "yaml"
    encoded_name = quote(f"{filename}.{ext}")

    headers = {
        "profile-update-interval": "24",
        "Content-Disposition": f"attachment; filename*=UTF-8''{encoded_name}",
    }
    if t == "singbox":
        media_type = "application/json; charset=utf-8"
    elif t == "base64":
        media_type = "text/plain; charset=utf-8"
    else:
        media_type = "text/yaml; charset=utf-8"
    return Response(content=output, media_type=media_type, headers=headers)


@app.get("/api/state", dependencies=[Depends(verify_admin)])
async def get_state():
    store = await load_store()
    proxies, _ = collect_all_proxies(store)
    # admin_password_hash 是内部凭证，不下发给前端
    settings = {k: v for k, v in store["settings"].items()
                if k != "admin_password_hash"}
    groups = build_proxy_groups(
        proxies, store["settings"], store.get("custom_groups", [])
    )
    available_targets = [g["name"] for g in groups] + ["DIRECT", "REJECT"]
    return {
        "settings": settings,
        "nodes": store["nodes"],
        "subscriptions": store["subscriptions"],
        "custom_groups": store.get("custom_groups", []),
        "custom_rules": store.get("custom_rules", []),
        "available_targets": available_targets,
        "parsed_count": len(proxies),
        # _raw_uri 是内部元数据，不下发给前端
        "parsed_proxies": [
            {k: v for k, v in p.items() if k != "_raw_uri"} for p in proxies
        ],
    }


def _backfill_fingerprints(store: dict) -> set:
    """给历史节点记录补指纹，返回已存在的指纹集合。"""
    settings = store.get("settings", {})
    existing_fp = set()
    for node in store.get("nodes", []):
        fp = node.get("fingerprint", "")
        if not fp and node.get("uri"):
            p = parse_single_line(
                node["uri"],
                vps_tag=node.get("vps_tag", ""),
                auto_emoji=settings.get("auto_emoji", True),
                prepend_vps_tag=settings.get("prepend_vps_tag", True),
            )
            if p:
                fp = p["fingerprint"]
                node["fingerprint"] = fp
        if fp:
            existing_fp.add(fp)
    return existing_fp


@app.post("/api/nodes", dependencies=[Depends(verify_admin)])
async def add_nodes_batch(req: NodeBatchCreate):
    store = await load_store()
    settings = store["settings"]
    existing_fp = _backfill_fingerprints(store)

    added = 0
    skipped = 0
    for line in req.raw_input.splitlines():
        line_str = line.strip()
        if not line_str or line_str.startswith("#"):
            continue
        parsed = parse_single_line(
            line_str,
            vps_tag=req.vps_tag,
            auto_emoji=settings.get("auto_emoji", True),
            prepend_vps_tag=settings.get("prepend_vps_tag", True),
        )
        if parsed:
            fp = parsed["fingerprint"]
            if fp in existing_fp:
                skipped += 1
                continue
            existing_fp.add(fp)
            store["nodes"].append(
                {
                    "id": uuid.uuid4().hex[:10],
                    "vps_tag": req.vps_tag.strip() or "默认服务器",
                    "name": "",
                    "uri": line_str,
                    "enabled": req.enabled,
                    "priority": req.priority,
                    "fingerprint": fp,
                }
            )
            added += 1

    await save_store(store)
    return {"ok": True, "added": added, "skipped_duplicates": skipped}


@app.put("/api/nodes/{node_id}", dependencies=[Depends(verify_admin)])
async def update_node(node_id: str, req: NodeUpdate):
    store = await load_store()
    for node in store["nodes"]:
        if node["id"] == node_id:
            if req.vps_tag is not None:
                node["vps_tag"] = req.vps_tag
            if req.name is not None:
                node["name"] = req.name
            if req.uri is not None:
                node["uri"] = req.uri
                # URI 变了，指纹重算
                p = parse_single_line(req.uri, vps_tag=node.get("vps_tag", ""))
                node["fingerprint"] = p["fingerprint"] if p else ""
            if req.enabled is not None:
                node["enabled"] = req.enabled
            if req.priority is not None:
                node["priority"] = req.priority
            await save_store(store)
            return {"ok": True}
    raise HTTPException(status_code=404, detail="节点不存在")


@app.delete("/api/nodes/{node_id}", dependencies=[Depends(verify_admin)])
async def delete_node(node_id: str):
    store = await load_store()
    store["nodes"] = [n for n in store["nodes"] if n["id"] != node_id]
    await save_store(store)
    return {"ok": True}


@app.post("/api/nodes/batch-toggle", dependencies=[Depends(verify_admin)])
async def batch_toggle_vps(req: BatchToggleRequest):
    store = await load_store()
    count = 0
    for node in store["nodes"]:
        if node.get("vps_tag") == req.vps_tag:
            node["enabled"] = req.enabled
            count += 1
    await save_store(store)
    return {"ok": True, "updated": count}


@app.post("/api/nodes/batch-delete", dependencies=[Depends(verify_admin)])
async def batch_delete_nodes(req: NodeBatchDeleteRequest):
    store = await load_store()
    wanted = set(req.node_ids or [])
    before = len(store.get("nodes", []))
    store["nodes"] = [n for n in store["nodes"] if n.get("id") not in wanted]
    deleted = before - len(store["nodes"])
    await save_store(store)
    return {"ok": True, "deleted": deleted}


async def _tcp_ping(
    host: str, port: int, sem: asyncio.Semaphore
) -> "tuple[str, int]":
    """TCP 握手测速。返回 (status, latency_ms)，失败时 latency 为 -1。"""
    async with sem:
        start = time.perf_counter()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3.0
            )
            latency = int((time.perf_counter() - start) * 1000)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return ("online", latency)
        except Exception:
            return ("offline", -1)


@app.post("/api/nodes/ping", dependencies=[Depends(verify_admin)])
async def ping_nodes(req: PingRequest = None):
    """节点 TCP 实时延迟与存活检测。node_ids 为空则测全部节点。"""
    store = await load_store()
    nodes = store.get("nodes", [])
    node_ids = (req.node_ids if req else None) or None
    if node_ids:
        wanted = set(node_ids)
        nodes = [n for n in nodes if n.get("id") in wanted]

    sem = asyncio.Semaphore(20)

    async def _one(node: dict) -> "tuple[str, str, int]":
        nid = node.get("id", "")
        try:
            uri = (node.get("uri") or "").strip()
            parsed = (
                parse_single_line(uri, vps_tag=node.get("vps_tag", "")) if uri else None
            )
            server = parsed.get("server") if parsed else None
            port = int(parsed["port"]) if parsed and parsed.get("port") else 0
            if not server or not port:
                return (nid, "offline", -1)
        except Exception:
            return (nid, "offline", -1)
        status, latency = await _tcp_ping(str(server), port, sem)
        return (nid, status, latency)

    results: Dict[str, dict] = {}
    for nid, status, latency in await asyncio.gather(*(_one(n) for n in nodes)):
        results[nid] = {"status": status, "latency": latency}
    return {"ok": True, "results": results}


@app.post("/api/subs", dependencies=[Depends(verify_admin)])
async def add_sub(req: SubCreate):
    store = await load_store()
    new_sub = {
        "id": uuid.uuid4().hex[:10],
        "name": req.name.strip(),
        "url": req.url.strip(),
        "prefix": req.prefix,
        "exclude_regex": req.exclude_regex,
        "enabled": req.enabled,
        "cached_proxies": [],
        "last_updated": "未刷新",
    }
    await fetch_single_subscription(new_sub, store["settings"])
    store["subscriptions"].append(new_sub)
    await save_store(store)
    return {"ok": True, "sub": new_sub}


@app.put("/api/subs/{sub_id}", dependencies=[Depends(verify_admin)])
async def update_sub(sub_id: str, req: SubUpdate):
    store = await load_store()
    for sub in store["subscriptions"]:
        if sub["id"] == sub_id:
            if req.name is not None:
                sub["name"] = req.name
            if req.url is not None:
                sub["url"] = req.url
            if req.prefix is not None:
                sub["prefix"] = req.prefix
            if req.exclude_regex is not None:
                sub["exclude_regex"] = req.exclude_regex
            if req.enabled is not None:
                sub["enabled"] = req.enabled
            await save_store(store)
            return {"ok": True}
    raise HTTPException(status_code=404, detail="订阅源不存在")


@app.delete("/api/subs/{sub_id}", dependencies=[Depends(verify_admin)])
async def delete_sub(sub_id: str):
    store = await load_store()
    store["subscriptions"] = [s for s in store["subscriptions"] if s["id"] != sub_id]
    await save_store(store)
    return {"ok": True}


_GROUP_TYPES = ("select", "url-test", "fallback")
_RULE_TYPES = ("DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN", "IP-CIDR", "PROCESS-NAME")


def _validate_group_type(gtype: str) -> str:
    gtype = (gtype or "select").strip().lower()
    if gtype not in _GROUP_TYPES:
        raise HTTPException(status_code=400, detail="不支持的策略组类型")
    return gtype


def _validate_regex(rx: str) -> str:
    rx = (rx or "").strip()
    if rx:
        try:
            re.compile(rx)
        except re.error:
            raise HTTPException(status_code=400, detail="节点匹配正则不合法")
    return rx


@app.post("/api/groups", dependencies=[Depends(verify_admin)])
async def add_group(req: CustomGroupCreate):
    name = (req.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="分流组名称不能为空")
    store = await load_store()
    groups = store.setdefault("custom_groups", [])
    if any(g.get("name") == name for g in groups):
        raise HTTPException(status_code=400, detail="分流组名称已存在")
    new_group = {
        "id": uuid.uuid4().hex[:10],
        "name": name,
        "type": _validate_group_type(req.type),
        "vps_filter": (req.vps_filter or "").strip(),
        "name_regex": _validate_regex(req.name_regex),
        "include_direct": bool(req.include_direct),
        "enabled": bool(req.enabled),
    }
    groups.append(new_group)
    await save_store(store)
    return {"ok": True, "group": new_group}


@app.put("/api/groups/{group_id}", dependencies=[Depends(verify_admin)])
async def update_group(group_id: str, req: CustomGroupUpdate):
    store = await load_store()
    for g in store.get("custom_groups", []):
        if g["id"] == group_id:
            if req.name is not None:
                name = req.name.strip()
                if not name:
                    raise HTTPException(status_code=400, detail="分流组名称不能为空")
                if any(x.get("name") == name and x["id"] != group_id
                       for x in store["custom_groups"]):
                    raise HTTPException(status_code=400, detail="分流组名称已存在")
                g["name"] = name
            if req.type is not None:
                g["type"] = _validate_group_type(req.type)
            if req.vps_filter is not None:
                g["vps_filter"] = req.vps_filter.strip()
            if req.name_regex is not None:
                g["name_regex"] = _validate_regex(req.name_regex)
            if req.include_direct is not None:
                g["include_direct"] = bool(req.include_direct)
            if req.enabled is not None:
                g["enabled"] = bool(req.enabled)
            await save_store(store)
            return {"ok": True, "group": g}
    raise HTTPException(status_code=404, detail="分流组不存在")


@app.delete("/api/groups/{group_id}", dependencies=[Depends(verify_admin)])
async def delete_group(group_id: str):
    store = await load_store()
    groups = store.get("custom_groups", [])
    store["custom_groups"] = [g for g in groups if g.get("id") != group_id]
    if len(store["custom_groups"]) == len(groups):
        raise HTTPException(status_code=404, detail="分流组不存在")
    await save_store(store)
    return {"ok": True}


def _validate_rule_type(rule_type: str) -> str:
    rule_type = (rule_type or "DOMAIN-SUFFIX").strip().upper()
    if rule_type not in _RULE_TYPES:
        raise HTTPException(status_code=400, detail="不支持的规则类型")
    return rule_type


@app.post("/api/rules", dependencies=[Depends(verify_admin)])
async def add_rules(req: CustomRuleCreate):
    # value 支持逗号 / 换行分隔，一次填入多个批量生成
    values = [
        v.strip() for v in re.split(r"[\n,，]+", req.value or "") if v.strip()
    ]
    if not values:
        raise HTTPException(status_code=400, detail="匹配内容不能为空")
    rule_type = _validate_rule_type(req.rule_type)
    store = await load_store()
    rules = store.setdefault("custom_rules", [])
    created = []
    for v in values:
        nr = {
            "id": uuid.uuid4().hex[:10],
            "rule_type": rule_type,
            "value": v,
            "target": (req.target or "🚀 节点选择").strip(),
            "comment": (req.comment or "").strip(),
            "enabled": bool(req.enabled),
        }
        rules.append(nr)
        created.append(nr)
    await save_store(store)
    return {"ok": True, "added": len(created), "rules": created}


@app.put("/api/rules/{rule_id}", dependencies=[Depends(verify_admin)])
async def update_rule(rule_id: str, req: CustomRuleUpdate):
    store = await load_store()
    for r in store.get("custom_rules", []):
        if r["id"] == rule_id:
            if req.rule_type is not None:
                r["rule_type"] = _validate_rule_type(req.rule_type)
            if req.value is not None:
                value = req.value.strip()
                if not value:
                    raise HTTPException(status_code=400, detail="匹配内容不能为空")
                r["value"] = value
            if req.target is not None:
                r["target"] = req.target.strip()
            if req.comment is not None:
                r["comment"] = req.comment.strip()
            if req.enabled is not None:
                r["enabled"] = bool(req.enabled)
            await save_store(store)
            return {"ok": True, "rule": r}
    raise HTTPException(status_code=404, detail="分流规则不存在")


@app.delete("/api/rules/{rule_id}", dependencies=[Depends(verify_admin)])
async def delete_rule(rule_id: str):
    store = await load_store()
    rules = store.get("custom_rules", [])
    store["custom_rules"] = [r for r in rules if r.get("id") != rule_id]
    if len(store["custom_rules"]) == len(rules):
        raise HTTPException(status_code=404, detail="分流规则不存在")
    await save_store(store)
    return {"ok": True}


@app.post("/api/subs/refresh", dependencies=[Depends(verify_admin)])
async def refresh_all_subs():
    store = await load_store()
    total_fetched = 0
    for sub in store["subscriptions"]:
        if sub.get("enabled", True):
            proxies = await fetch_single_subscription(sub, store["settings"])
            total_fetched += len(proxies)
    await save_store(store)
    return {"ok": True, "total_fetched": total_fetched}


@app.put("/api/settings", dependencies=[Depends(verify_admin)])
async def update_settings(req: SettingsUpdate):
    store = await load_store()
    s = store["settings"]
    if req.sub_filename is not None:
        s["sub_filename"] = req.sub_filename
    if req.test_url is not None:
        s["test_url"] = req.test_url
    if req.test_interval is not None:
        s["test_interval"] = req.test_interval
    if req.test_tolerance is not None:
        s["test_tolerance"] = req.test_tolerance
    if req.auto_emoji is not None:
        s["auto_emoji"] = req.auto_emoji
    if req.prepend_vps_tag is not None:
        s["prepend_vps_tag"] = req.prepend_vps_tag
    if req.udp_default is not None:
        s["udp_default"] = req.udp_default
    if req.sub_refresh_interval is not None:
        try:
            s["sub_refresh_interval"] = max(600, int(req.sub_refresh_interval))
        except (TypeError, ValueError):
            pass
    if req.reset_token:
        s["sub_token"] = secrets.token_urlsafe(18)

    await save_store(store)
    return {"ok": True, "settings": s}


@app.post("/api/settings/password", dependencies=[Depends(verify_admin)])
async def change_password(req: PasswordChangeRequest):
    """修改管理密码。存 sha256 哈希，不存原文；忘记后删 data/store.json
    里的 admin_password_hash 即回退到环境变量/默认密码。"""
    store = await load_store()
    s = store["settings"]
    if not _check_password(req.current_password, s):
        raise HTTPException(status_code=401, detail="当前密码不正确")
    new_pw = (req.new_password or "").strip()
    if len(new_pw) < 6:
        raise HTTPException(status_code=400, detail="新密码至少 6 位")
    if hmac.compare_digest(_hash_password(new_pw),
                           _hash_password(req.current_password or "")):
        raise HTTPException(status_code=400, detail="新密码不能与当前密码相同")
    s["admin_password_hash"] = _hash_password(new_pw)
    await save_store(store)
    return {"ok": True}


@app.get("/api/template", dependencies=[Depends(verify_admin)])
async def get_template():
    return {"content": load_template()}


@app.put("/api/template", dependencies=[Depends(verify_admin)])
async def put_template(req: TemplateUpdate):
    save_template(req.content)
    return {"ok": True}


@app.get("/api/preview", dependencies=[Depends(verify_admin)])
async def preview_config(
    target: str = Query(default="mihomo", pattern="^(mihomo|singbox)$"),
):
    """配置预览：mihomo 返回 YAML 文本，singbox 返回格式化 JSON 文本。"""
    store = await load_store()
    if target == "singbox":
        from app.singbox import generate_singbox_config

        cfg = json.loads(generate_singbox_config(store))
        return {
            "target": "singbox",
            "json": json.dumps(cfg, ensure_ascii=False, indent=2),
        }
    yaml_text = generate_subscription_output(store, target="mihomo")
    return {"target": "mihomo", "yaml": yaml_text}


@app.get("/api/backup/export", dependencies=[Depends(verify_admin)])
async def export_backup():
    """导出全量备份：store 完整数据 + base_template 文本。"""
    store = await load_store()
    return {
        "ok": True,
        "backup": {
            "app": "SubHub",
            "version": "1.4",
            "exported_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime()),
            "store": store,
            "base_template": load_template(),
        },
    }


@app.post("/api/backup/import", dependencies=[Depends(verify_admin)])
async def import_backup(req: BackupImportRequest):
    """导入全量备份：校验基本结构后写入 store.json（及可选的模板）。"""
    data = req.backup or {}
    store_data = data.get("store")
    if not isinstance(store_data, dict):
        raise HTTPException(status_code=400, detail="备份缺少 store 对象")
    settings = store_data.get("settings")
    if not isinstance(settings, dict) or not settings.get("sub_token"):
        raise HTTPException(status_code=400, detail="备份缺少 settings/sub_token")
    if not isinstance(store_data.get("nodes"), list):
        raise HTTPException(status_code=400, detail="备份缺少 nodes 列表")
    if not isinstance(store_data.get("subscriptions"), list):
        raise HTTPException(status_code=400, detail="备份缺少 subscriptions 列表")
    await save_store(store_data)
    tpl = data.get("base_template")
    if isinstance(tpl, str) and tpl.strip():
        save_template(tpl)
    return {
        "ok": True,
        "restored_nodes": len(store_data["nodes"]),
        "restored_subs": len(store_data["subscriptions"]),
    }
