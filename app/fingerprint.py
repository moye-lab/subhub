"""节点指纹去重：按连接参数算 sha256，改名不影响判定。

指纹输入 = 协议 + 归一化服务器名(小写、去尾点) + 端口 + 全部连接参数；
显示名(name)与指纹字段本身不参与计算。同一条线路换了个备注名，
指纹相同，视为重复节点。
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict


def compute_fingerprint(proxy: Dict[str, Any]) -> str:
    try:
        port = int(proxy.get("port", 0))
    except (TypeError, ValueError):
        port = 0
    payload = {
        "protocol": str(proxy.get("type", "")),
        "server": str(proxy.get("server", "")).lower().rstrip("."),
        "port": port,
        # type/server/port 已在顶层归一化，config 里不再重复携带，
        # 避免同一字段两种写法导致指纹漂移
        "config": {
            k: v
            for k, v in proxy.items()
            if k not in ("name", "fingerprint", "type", "server", "port", "_raw_uri")
        },
    }
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
