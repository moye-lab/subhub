# SubHub — 个人多 VPS 节点订阅管理系统

把分布在多台 VPS 上的单节点分享链接、外部面板订阅统一汇聚，
一键生成 Mihomo / Sing-box / Shadowrocket 三端订阅，带 AI 专线防封锁、
地区自动分组、自定义分流组与分流规则。

## 安装（Docker Compose）

```bash
git clone https://github.com/moye-lab/subhub.git
cd subhub
```

改管理密码（二选一）。

**方式一：一行命令直接改（推荐）**

```bash
sed -i 's/admin123/你的密码/' docker-compose.yml
```

**方式二：用 .env 文件（适合把配置留档）**

```bash
cp .env.example .env
```

再用编辑器把 `.env` 里的 `ADMIN_PASSWORD` 改成你的密码。

启动：

```bash
docker compose up -d --build
```

浏览器打开 `http://<服务器IP>:18080`，输入管理密码进入控制台。

> 默认映射宿主机 `18080` 端口（容器内仍是 `8080`）；如需修改，改
> `docker-compose.yml` 里 `"18080:8080"` 冒号左边的宿主机端口即可。

健康检查：`curl http://<服务器IP>:18080/api/health`
正常返回 `{"status":"ok","version":"1.0.0"}`。

> 所有数据都在 `./data` 目录（单文件 JSON），升级、重装、迁移只要这个
> 目录在就丢不了；`./data` 已在 `.gitignore` 中，不会误提交。

## 卸载（分三档，按需执行）

```bash
cd subhub
```

```bash
# 第一档：仅停服 —— 停止并删除容器，镜像和数据都保留，
# 随时 docker compose up -d 即可恢复
docker compose down
```

```bash
# 第二档：删干净程序 —— 连 Docker 镜像一起删（数据仍在 ./data）
docker compose down --rmi all
```

```bash
# 第三档：彻底清除 —— 再删掉 ./data，
# 节点、订阅源、管理密码、分流规则全部清空，不可恢复
rm -rf ./data
```

整目录都不要了：

```bash
cd .. && rm -rf subhub
```

## 更新到新版本（数据不受影响）

```bash
# 1. 先停掉旧版
cd subhub && docker compose down && cd ..

# 2. 拉新版，把数据目录拷过去
git clone https://github.com/moye-lab/subhub.git subhub-new
cp -r subhub/data subhub-new/data

# 3. 启动新版（端口、密码等配置按需照旧调整）
cd subhub-new && docker compose up -d --build

# 4. 确认新版页面正常后，删掉旧目录并改名
cd .. && rm -rf subhub && mv subhub-new subhub
```

## 本地运行（无 Docker）

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
ADMIN_PASSWORD=你的密码 uvicorn app.main:app --host 0.0.0.0 --port 18080
```

数据目录可用 `DATA_DIR` 环境变量指定，默认 `./data`。

## 使用流程

1. **订阅概览**：4 张客户端卡片（Mihomo / Sing-box / Shadowrocket / 智能自适应），
   复制链接、扫码或一键唤起客户端导入；下方是 VPS 分组速控与生效节点一览。
2. **节点与订阅源**：按 VPS 分组管理自建节点（批量导入 / 启停 / TCP 测速 /
   批量删除）；下方聚合外部面板订阅（3x-ui / Clash YAML / Base64），8 秒超时，
   拉取失败自动用缓存兜底，后台每 6 小时自动同步。
3. **分流与策略组**：自定义分流组（按 VPS 标签 / 节点名正则圈节点，
   select / url-test / fallback）与自定义分流规则（域名后缀 / 关键字 /
   完整域名 / IP 段 / 进程名，置顶注入），Mihomo 与 sing-box 双引擎同步生效。
4. **系统设置**：全局测速与命名参数、修改管理密码、重置订阅 Token、
   全量备份导出 / 导入、底座 YAML 模板编辑。

订阅输出（`GET /sub/{token}`，`target` 不填则按 User-Agent 智能分发）：

| `target` | 输出 |
| ---- | ---- |
| `mihomo`（默认） | 完整 Mihomo 分流 YAML |
| `singbox` | sing-box 原生 JSON（分组与 Mihomo 一致） |
| `base64` | 通用 Base64 订阅（节点名已同步最终修饰名，含远程节点） |
| `proxies` | 纯节点池（供 proxy-providers 引用） |

## 核心特性

- **AI 专线防封锁**：`🤖 AI 专线` / `⚡ AI 自动优选` 自动剔除 HK / CN / MO / RU 节点
- **空地区组自动裁剪**：没有某地区节点时，该策略组自动删除且不留悬空引用
- **指纹去重**：按协议+服务器+端口+连接参数算 sha256，改名不影响判定，
  手动导入与远程订阅拉到同一条线路只保留一份
- **节点优先级**：`priority` 越小在 `🛡️ 故障转移` 里越靠前；支持整组一键启停
- **命名**：自动识别地区加国旗 Emoji，可选附加 `[VPS标签]` 前缀，同名自动 `#2` 去重
- **底座模板**：`data/base_template.yaml` 可视化编辑（DNS / Sniffer / rule-providers / rules）
- **零数据库**：`data/store.json` 单文件存储，备份拷走 `./data` 即可
- **原子写入**：配置保存先写临时文件再原子替换，异常断电不损坏 JSON；
  万一损坏自动改名留档并重建默认结构，服务不崩
- **智能订阅分发**：`/sub/{token}` 不带 `target` 时按 `User-Agent` 自动分发
  （sing-box 系 → JSON，Shadowrocket/v2rayN 系 → Base64，其余 → Mihomo YAML）
- **节点 TCP 测速**：`POST /api/nodes/ping` 并发测全部节点握手延迟，前端一键测速徽章
- **后台自动刷新**：远程订阅每 `sub_refresh_interval` 秒（默认 6 小时，最小 10 分钟）自动更新缓存
- **登录防爆破**：同一 IP 5 分钟内连错 5 次锁定 15 分钟
- **一键备份恢复**：`GET /api/backup/export` 导出全量 JSON，`POST /api/backup/import` 恢复
- **自定义分流组**：`POST /api/groups` 按 VPS 标签 / 名称正则圈定节点建组
  （select/url-test/fallback），Mihomo 与 sing-box 双引擎同步生效
- **自定义分流规则**：`POST /api/rules` 批量添加（逗号/换行分隔），
  插到规则最前面；目标不存在自动回退 `🚀 节点选择`，Mihomo 拒绝启动保护
- **节点批量删除**：`POST /api/nodes/batch-delete`
- **Base64 订阅名称同步**：`?target=base64` 输出全部有效节点（含远程订阅缓存），
  `#fragment` 统一为最终修饰名（含 `[VPS标签]` / 国旗 Emoji）；
  远程节点按协议反向拼装为标准分享链接
- **健康检查**：`GET /api/health` 免鉴权返回版本信息，Docker 镜像内置 `HEALTHCHECK`

## 忘记管理密码

删掉 `data/store.json` 里的 `admin_password_hash` 一行，重启容器后即回退到
`docker-compose.yml`（或 `.env`）里的启动密码。平时也可以在「系统设置」页
直接修改（只存 sha256 哈希，不存原文）。

## API 速览（管理接口需 `X-Admin-Token` 头）

| 方法 | 路径 | 说明 |
| ---- | ---- | ---- |
| GET | `/sub/{token}?target=auto\|mihomo\|clash\|singbox\|sing-box\|proxies\|base64` | 订阅输出（默认 auto 按 UA 分发） |
| GET | `/api/state` | 全量状态（设置/节点/订阅/解析结果） |
| POST | `/api/nodes` | 批量导入节点 |
| POST | `/api/nodes/ping` | 节点 TCP 延迟与存活检测（可传 node_ids 只测部分） |
| POST | `/api/nodes/batch-toggle` | 整组启停 |
| POST | `/api/subs` · `/api/subs/refresh` | 添加 / 刷新远程订阅 |
| PUT | `/api/settings` | 设置（含重置订阅 Token、自动刷新间隔） |
| POST | `/api/settings/password` | 修改管理密码（字段 `current_password` / `new_password`） |
| GET/PUT | `/api/template` | 底座 YAML 模板读写 |
| GET | `/api/preview?target=mihomo\|singbox` | 预览 Mihomo YAML / Sing-box JSON |
| GET | `/api/backup/export` | 导出全量备份 JSON |
| POST | `/api/backup/import` | 导入备份恢复 |
| POST/PUT/DELETE | `/api/groups` · `/api/groups/{id}` | 自定义分流组 CRUD |
| POST/PUT/DELETE | `/api/rules` · `/api/rules/{id}` | 自定义分流规则 CRUD |
| POST | `/api/nodes/batch-delete` | 批量删除节点 |
| GET | `/api/health` | 健康检查（免鉴权） |

## 测试

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
.venv/bin/python -m pytest tests/ -q
```

## 目录结构

```text
subhub/
├── app/
│   ├── main.py            # FastAPI 路由、鉴权、订阅分发
│   ├── __init__.py        # 版本号（__version__）
│   ├── config.py          # DATA_DIR / ADMIN_PASSWORD 等配置
│   ├── parser.py          # 全协议节点解析 + 国旗 Emoji 命名
│   ├── fingerprint.py     # 节点指纹去重
│   ├── fetcher.py         # 远程订阅拉取与缓存兜底
│   ├── generator.py       # 订阅生成：Mihomo / Base64 / 自定义分流
│   ├── singbox.py         # sing-box 原生 JSON 生成
│   ├── storage.py         # JSON 原子写入 + 默认模板
│   ├── models.py          # Pydantic 模型
│   └── static/index.html  # Vue3 + Tailwind 单文件管理面板
├── tests/                 # 单元测试（pytest）
├── data/                  # 运行数据（git 忽略）：store.json / base_template.yaml
├── Dockerfile             # 含 HEALTHCHECK
├── docker-compose.yml     # 一键部署（宿主机端口 18080，可改）
├── .env.example           # 环境变量模板（ADMIN_PASSWORD）
└── requirements.txt
```
