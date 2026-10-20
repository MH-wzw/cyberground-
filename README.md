# CyberGuard — DDoS 防护监控平台

面向 **2026 年第十四届全国大学生数字媒体科技作品及创意竞赛**（赛道：移动与网络应用开发）的
DDoS 防护与攻击态势感知平台。

Web 端提供全球攻击态势、攻击链路分析、登录暴力破解检测、告警处置、IP 黑名单与通知配置；
检测侧真实实现 5 条暴力破解检测规则；主机侧通过 `psutil` 采集真实指标。
**所有网络攻击数据均由沙箱模拟器在内存内推演，不产生任何真实网络报文。**

## 作品简介

> 本作品是面向安全运营教学与攻防演练的 Web 安全平台。平台内置 5 条暴力破解检测规则，以滑动窗口与双指针算法覆盖高频失败、撞库、破解得手、字典与慢速破解；告警按风险分级，来源 IP 自动封禁 12 小时至 30 天，并在请求入口真实生效。DDoS 侧用内存状态机推演 6 类攻击，按平静、攀升、突袭、消退四阶段构造浪潮，攻击源取自固定肉鸡池；数据经 WebSocket 实时推送，以热力图、攻击链桑基图、可疑攻击源、受影响服务四重视角呈现，高危告警去重聚合后邮件推送值班人。全程不产生真实网络报文。

---

## 1. 快速开始

### 1.1 环境要求

| 项目 | 版本 |
|---|---|
| Python | 3.13+（开发与验证于 3.14；与官网填报口径一致） |
| 操作系统 | Windows 10/11（Linux/macOS 亦可运行） |
| 网络 | **无需联网** —— 前端依赖全部本地化于 `static/vendor/` |

### 1.2 安装

```bat
cd /d E:\CyberGround
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 1.3 启动

仓库根目录提供两个启动脚本：

| 脚本 | DEMO_MODE | 用途 |
|---|---|---|
| **`start_demo.bat`** | `1` | **演示/评审用**。启用前端「暴力破解演示控制台」的 POST 接口（仅允许本机来源） |
| `start.bat` | `0` | 正式模式。演示接口不注册，攻击数据仍由模拟器推演 |

双击其一即可；等价的手动命令：

```bat
set PYTHONIOENCODING=utf-8
set DEMO_MODE=1
.venv\Scripts\python.exe app.py
```

启动后访问 **http://127.0.0.1:5000**。

> ⚠ **修改模板后必须重启进程**：应用以 `use_reloader=False` 运行，Jinja 模板会被缓存。

### 1.4 登录

| 账号 | 密码 | 角色 |
|---|---|---|
| `admin` | `Admin@123` | 管理员（可执行处置操作） |

默认账号可用环境变量覆盖（**首次启动建库时生效**）：

```bat
set CYBERGUARD_ADMIN_USER=youraccount
set CYBERGUARD_ADMIN_PASS=yourStrongPassword
```

自助注册的账号一律为 **viewer（只读）**，服务端强制，不能自提权。

---

## 2. 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `DEMO_MODE` | `0` | `1` 时注册 `/api/demo/*` 演示接口，并限定请求来自本机 |
| `SECRET_KEY` | 随机一次性 | 会话签名密钥。**生产/演示建议固定注入**，否则每次重启旧会话失效 |
| `CYBERGUARD_ADMIN_USER` | `admin` | 初始管理员用户名 |
| `CYBERGUARD_ADMIN_PASS` | `Admin@123` | 初始管理员密码 |
| `CYBERGUARD_SMTP_HOST` | 空 | SMTP 服务器（留空则在数据库内配置） |
| `CYBERGUARD_SMTP_PORT` | `465` | 465 = SSL 直连；587 = STARTTLS |
| `CYBERGUARD_SMTP_USER` | 空 | 发件账号 |
| `CYBERGUARD_SMTP_PASS` | 空 | 发件授权码 / 密码 |
| `CYBERGUARD_SMTP_FROM` | 空 | 发件人显示地址 |
| `CYBERGUARD_SMTP_TLS` | `1` | `1` = SSL/TLS；`0` = STARTTLS |
| `PYTHONIOENCODING` | — | 建议设 `utf-8`，避免 Windows 控制台中文乱码 |

SMTP 亦可只在前端「通知配置」页填写，配置存于 `db.sqlite3` 的 `notify_config` 表；
**接口返回时会掩码为 `********`**，并提供 `_has_password` 标记。

---

## 3. 目录结构

```
CyberGround/
├── app.py                     Flask 应用：路由、鉴权守卫、WebSocket 推送、启动入口
├── config.py                  配置常量：检测阈值、攻击类型、地理映射、清洗节点
├── requirements.txt           Python 依赖
├── start.bat / start_demo.bat 启动脚本（正式 / 演示）
├── db.sqlite3                 SQLite 数据库（首次启动自动建表）
├── templates/                 14 个 Jinja2 模板（base.html 为公共外壳）
│   ├── base.html              侧边栏 + 内容容器 + 公共交互
│   ├── index.html             态势大屏
│   ├── heatmap.html           全球攻击地图（Canvas 2D 平面投影）
│   ├── attack_chain.html      攻击链分析（桑基图 + 时间线）
│   ├── logs.html              登录日志 + 登录攻击粒子
│   ├── alerts.html            告警管理
│   ├── blacklist.html         IP 黑名单
│   ├── notify.html            通知配置（仅管理员）
│   ├── users.html             用户管理（仅管理员）
│   ├── login.html / register.html / 403.html / blocked.html / doc_view.html
├── static/
│   ├── dark-theme.css         基础主题（历史令牌 + 通用组件）
│   ├── design-system.css      设计系统（调色板、卡片、网格、动效）
│   ├── shell.css              外壳层（侧边栏、内容容器、徽章）
│   ├── js/cyberguard.js       CSRF 注入、Toast、确认弹窗、主题色读取
│   ├── js/cg-theme.js         主题切换
│   └── vendor/                本地化第三方依赖（ECharts / Socket.IO / Bootstrap / jQuery）
├── utils/
│   ├── auth.py                用户与会话（PBKDF2-SHA256、角色、守卫装饰器）
│   ├── auth_routes.py         登录/注册/用户管理蓝图
│   ├── db_helper.py           SQLite 访问层（表结构、CRUD、迁移）
│   ├── detector.py            5 条暴力破解检测规则
│   ├── log_generator.py       模拟登录日志生成
│   ├── ddos_simulator.py      DDoS 沙箱模拟器（攻击波次状态机、地理分布、链路）
│   ├── host_metrics.py        psutil 真实主机指标
│   ├── notifier.py            告警邮件通知（去重、限速、投递日志）
│   └── notify_routes.py       通知配置蓝图
├── tests/
│   ├── test_all.py            unittest 单元测试（17 用例）
│   ├── test_ddos_notifier.py  模拟器与通知门控测试（21 用例）
│   └── auth_verify.py         鉴权矩阵黑盒回归脚本
└── docs/                      提交用文档（合规声明、数据来源、参赛字段等）
```

---

## 4. 测试

```bat
REM 单元测试（config / db_helper / log_generator / detector）
.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v

REM 鉴权矩阵回归（需先启动应用，默认连 127.0.0.1:5000）
.venv\Scripts\python.exe tests\auth_verify.py
```

`tests/auth_verify.py` 会真实登录并验证：

- 匿名访问页面 → 302，匿名查询接口 → 401
- 管理员全量访问与写操作
- 自助注册账号强制只读（防自提权）
- viewer 的写操作必须被服务端拒绝（带有效 CSRF 令牌时仍返回 403）

---

## 5. 数据来源与合规

平台把数据分为三类，并在界面上逐处标注：

| 类别 | 来源 | 标注 |
|---|---|---|
| **实时采集** | `psutil` 读取本机 CPU / 内存 / 磁盘 IO / 网卡吞吐 | `实时采集` |
| **真实数据** | SQLite 中的登录日志、告警、黑名单、用户与权限（由 5 条检测规则真实判定产生） | `真实数据` |
| **沙箱模拟** | DDoS 攻击事件、流量、地理分布、攻击链路（内存内推演，不产生真实报文） | `沙箱模拟` |

合规要点：

- **不采集、不存储任何真实用户凭证**。`login_logs.attempted_password` 仅存程序生成的弱口令样本，
  用于复现「字典攻击」场景。
- 攻击数据为模拟推演，**不会对任何目标发起真实请求**。
- 详细说明见 `docs/安全与合规声明.md`、`docs/数据来源说明.md`。

---

## 6. 常见问题

**Q：启动报 `OSError: [WinError 10048]`（端口被占用）**
A：5000 端口已有实例。关掉旧进程，或临时改用其他端口启动。

**Q：页面显示「连接中断」**
A：WebSocket 未连上。确认应用已启动且浏览器访问的是 `127.0.0.1:5000`（非 `file://`）。

**Q：改了模板没生效**
A：Flask 以 `use_reloader=False` 运行，模板被缓存 —— **重启进程**。

**Q：演示控制台的按钮点了没反应**
A：需要 `DEMO_MODE=1`（用 `start_demo.bat` 启动），且请求必须来自本机。

**Q：告警邮件发不出去**
A：先在「通知配置」页配置 SMTP 并点「发送测试邮件」；未配置时仅记录到投递日志。

**Q：`SECRET_KEY` 没设，会有影响吗**
A：会。未设置时每次启动生成一次性随机密钥，**重启后所有登录会话失效**。演示前建议固定注入。

---

## 7. 技术栈

| 层 | 选型 |
|---|---|
| Web 框架 | Flask |
| 实时推送 | Flask-SocketIO + eventlet（WebSocket） |
| 数据库 | SQLite（标准库 `sqlite3`） |
| 前端图表 | ECharts 5 |
| 前端框架 | 原生 JS + jQuery（无构建步骤） |
| 地图 / 粒子 | 纯 Canvas 2D 手绘，零外部库 |
| 主机指标 | psutil |
| 报表导出 | pandas + openpyxl |
| 密码学 | `werkzeug.security`（PBKDF2-SHA256） |
