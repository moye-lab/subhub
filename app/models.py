from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    password: str


class SettingsModel(BaseModel):
    sub_token: str
    sub_filename: str = "SubHub"
    test_url: str = "https://www.gstatic.com/generate_204"
    test_interval: int = 300
    test_tolerance: int = 50
    auto_emoji: bool = True
    prepend_vps_tag: bool = True
    udp_default: bool = True


class SettingsUpdate(BaseModel):
    sub_filename: Optional[str] = None
    test_url: Optional[str] = None
    test_interval: Optional[int] = None
    test_tolerance: Optional[int] = None
    auto_emoji: Optional[bool] = None
    prepend_vps_tag: Optional[bool] = None
    udp_default: Optional[bool] = None
    sub_refresh_interval: Optional[int] = None
    reset_token: Optional[bool] = False


class NodeItem(BaseModel):
    id: str
    vps_tag: str = "默认服务器"
    name: str = ""
    uri: str
    enabled: bool = True
    priority: int = 10
    fingerprint: str = ""


class NodeBatchCreate(BaseModel):
    vps_tag: str = "VPS-A"
    raw_input: str
    priority: int = 10
    enabled: bool = True


class NodeUpdate(BaseModel):
    vps_tag: Optional[str] = None
    name: Optional[str] = None
    uri: Optional[str] = None
    enabled: Optional[bool] = None
    priority: Optional[int] = None


class BatchToggleRequest(BaseModel):
    vps_tag: str
    enabled: bool


class SubItem(BaseModel):
    id: str
    name: str
    url: str
    enabled: bool = True
    prefix: str = ""
    exclude_regex: str = "剩余流量|到期|官网|套餐|重置"
    cached_proxies: List[Dict[str, Any]] = Field(default_factory=list)
    last_updated: str = ""


class SubCreate(BaseModel):
    name: str
    url: str
    prefix: str = ""
    exclude_regex: str = "剩余流量|到期|官网|套餐|重置"
    enabled: bool = True


class SubUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    prefix: Optional[str] = None
    exclude_regex: Optional[str] = None
    enabled: Optional[bool] = None


class TemplateUpdate(BaseModel):
    content: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


class PingRequest(BaseModel):
    # 为空则测全部节点；否则只测指定 id 的节点
    node_ids: Optional[List[str]] = None


class BackupImportRequest(BaseModel):
    backup: Dict[str, Any]


class CustomGroupItem(BaseModel):
    id: str
    name: str
    type: str = "select"
    vps_filter: str = ""
    name_regex: str = ""
    include_direct: bool = False
    enabled: bool = True


class CustomGroupCreate(BaseModel):
    name: str
    type: str = "select"
    vps_filter: str = ""
    name_regex: str = ""
    include_direct: bool = False
    enabled: bool = True


class CustomGroupUpdate(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    vps_filter: Optional[str] = None
    name_regex: Optional[str] = None
    include_direct: Optional[bool] = None
    enabled: Optional[bool] = None


class CustomRuleItem(BaseModel):
    id: str
    rule_type: str = "DOMAIN-SUFFIX"
    value: str
    target: str = "🚀 节点选择"
    comment: str = ""
    enabled: bool = True


class CustomRuleCreate(BaseModel):
    rule_type: str = "DOMAIN-SUFFIX"
    value: str
    target: str = "🚀 节点选择"
    comment: str = ""
    enabled: bool = True


class CustomRuleUpdate(BaseModel):
    rule_type: Optional[str] = None
    value: Optional[str] = None
    target: Optional[str] = None
    comment: Optional[str] = None
    enabled: Optional[bool] = None


class NodeBatchDeleteRequest(BaseModel):
    node_ids: List[str]
