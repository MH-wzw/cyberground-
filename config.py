"""
==============================================================================
  CyberGuard DDoS 防护监控平台 — 全局配置文件
==============================================================================
  本文件是项目的配置中心，所有可调参数集中管理，便于：
  1. 答辩现场快速调整检测灵敏度
  2. 不同场景下切换阈值（开发/生产环境）
  3. 规则引擎的统一参数入口

  设计原则：
  - 所有魔法数字集中于此，代码中不出现硬编码阈值
  - 按功能模块分区，注释说明每个参数的含义和单位
  - SECRET_KEY 生产环境应从环境变量注入
==============================================================================
"""

import os

# ======================== 数据库配置 ========================
# SQLite 数据库文件路径，当前目录下的 db.sqlite3
# 选择 SQLite 的原因：轻量级、零配置、适合教学演示和单机部署
DATABASE_PATH = "db.sqlite3"

# Flask 会话加密密钥 — 用于签名 session cookie
# 安全设计：不再提供可预测的硬编码兜底值。
# 优先读取环境变量 SECRET_KEY；未配置时由 app.py 生成一次性随机密钥
# （随机密钥的副作用是重启后旧会话失效，这正是安全上期望的行为）。
# 生产环境请固定注入：set SECRET_KEY=<足够长的随机字符串>
SECRET_KEY = os.environ.get("SECRET_KEY") or None

# Flask 调试模式 — 生产环境关闭
DEBUG = False

# 会话 Cookie 安全属性
SESSION_COOKIE_HTTPONLY = True      # 禁止 JavaScript 读取会话 Cookie（防 XSS 窃取）
SESSION_COOKIE_SAMESITE = "Lax"     # 缓解 CSRF
SESSION_COOKIE_NAME = "cyberguard_session"
PERMANENT_SESSION_LIFETIME = 8 * 3600   # 会话有效期 8 小时


# ======================== 暴力破解检测规则配置 ========================
# 以下配置定义了 5 条检测规则的阈值参数
# 每条规则对应一种常见的暴力破解攻击模式
# 调整这些参数可以实现从敏感（低阈值）到宽松（高阈值）的检测策略切换

DETECTION_RULES = {
    # 规则1：IP 高频失败攻击
    # 在指定时间窗口内，同一 IP 的失败登录次数达到阈值即触发告警
    "ip_failure_threshold": 10,      # 失败次数阈值（次）
    "ip_time_window": 5,             # 时间窗口（分钟）

    # 规则2：账号多 IP 攻击（撞库攻击）
    # 同一账号在指定时间内被多个不同 IP 尝试登录
    "account_ip_threshold": 8,       # 不同IP数量阈值（个）
    "account_time_window": 10,       # 时间窗口（分钟）

    # 规则3：高频失败 + 零星成功攻击（暴力破解成功）
    # 在时间窗口内失败次数极高 + 成功次数极少 → 疑似暴力破解成功
    "high_failure_threshold": 20,    # 高失败次数阈值（次）
    "success_threshold": 2,          # 低成功次数阈值（次）
    "high_time_window": 15,          # 时间窗口（分钟）

    # 规则5：慢速暴力破解
    # 攻击者降低请求频率以规避检测，但持续较长时间
    "slow_brute_force_threshold": 10,           # 最少尝试次数
    "slow_brute_force_interval_minutes": 30,    # 平均间隔阈值（分钟）
}

# 常见弱密码库（用于字典攻击检测）
# 数据来源：历年数据泄露统计中最常见的弱密码
# 可随时扩充以增强检测覆盖度
COMMON_WEAK_PASSWORDS = {
    "admin", "root", "123456", "password", "123123", "abc123", "111111",
    "123456789", "1234567", "1234", "000000", "123321", "654321",
    "iloveyou", "toor", "guest", "test", "user"
}


# ======================== DDoS 防护监控配置 ========================
# 定义 DDoS 模拟器的攻击检测阈值和流量基线参数

DDOS_RULES = {
    # 各类型攻击的流量阈值（包/秒 或 请求/秒）
    "syn_flood_threshold": 5000,      # SYN Flood 半连接攻击
    "udp_flood_threshold": 8000,      # UDP Flood 大流量攻击
    "http_flood_threshold": 3000,     # HTTP Flood 应用层攻击（rps）
    "dns_amp_threshold": 2000,        # DNS 放大攻击反射流量

    # 全局流量阈值
    "bandwidth_threshold_mbps": 800,  # 总带宽阈值（Mbps）
    "connection_threshold": 10000,    # 并发连接数阈值
    "traffic_window_seconds": 60,     # 流量统计滑动窗口（秒）
    "mitigation_delay_seconds": 5,    # 检测到缓解的平均延迟（秒）
}


# ======================== DDoS 攻击浪潮参数 ========================
# 设计目标：把"恒定速率随机出攻击"改成有起伏的"攻击浪潮"结构。
#
# 原实现是每个 tick 固定 25% 概率出 1~3 个攻击 —— 这是一个恒定速率的
# 泊松过程：无论观察 10 秒还是 10 分钟，攻击到达速率都完全一样。
# 真实 DDoS 是事件型的：大部分时间静默，来的时候集中爆发，然后消退。
#
# 现在引入四阶段状态机：
#     calm(平静) → rise(攀升) → surge(突袭) → decay(消退) → calm ...
# 每个阶段有自己的持续时长与出攻击速率，形成"攻击浪潮"。
#
# 时长单位：tick（1 tick = 1.5 秒）。区间用三角分布抽样，
# 众数偏小 → 短周期多、长周期少，符合真实攻击间隔的长尾特征。
#
# 现场演示提示：把 calm 的 low/high 调小，可以立刻看到攻击变密，
# 这是"参数如何影响攻击节奏"的直观展示点。
ATTACK_WAVE = {
    # 各阶段：(最短 tick, 最长 tick, 三角分布众数位置比例)
    "durations": {
        "calm":  (60, 130, 0.30),   # 平静期 1.5~3.3 分钟
        "rise":  (20,  40, 0.40),   # 攀升期 30~60 秒
        "surge": (40,  80, 0.35),   # 突袭期 1~2 分钟
        "decay": (30,  60, 0.40),   # 消退期 45~90 秒
    },
    # 各阶段出攻击行为：(每 tick 命中概率, 命中后生成数量下限, 上限)
    "profiles": {
        "calm":  (0.02, 1, 1),      # 约 0.8 个/分钟
        "rise":  (0.35, 1, 2),      # 约 14 个/分钟
        "surge": (0.70, 2, 3),      # 理论 70 个/分钟（0.70 x 2.5 / 1.5s x 60）
                                     # 实测长跑均值约 13 个/分钟（含阶段切换摊薄）。
                                     # 上限这样定的原因：事件存活 40 tick(60 秒)，
                                     # 因此突袭期活跃攻击数峰值约 60~80 ——
                                     # 既能形成明显高峰，又不会让首页列表长到无法阅读。
        "decay": (0.25, 1, 2),      # 约 10 个/分钟
    },
    # 阶段展示名称（前端徽章使用）
    "labels": {
        "calm":  "平静期",
        "rise":  "攀升期",
        "surge": "突袭期",
        "decay": "消退期",
    },
    # 攻击事件存活上限（tick）。突袭期会密集生成事件，若不加淘汰，
    # "攻击中/检测中"的事件会永久堆积，活跃攻击数越滚越大而失真。
    "event_ttl_ticks": 40,          # 约 60 秒后自动从活跃列表淘汰
}

# 僵尸网络规模 —— 攻击源从固定肉鸡池中抽取（可重复出现）
# 真实 DDoS 的特征是"同一批肉鸡在 C2 指挥下反复攻击"，
# 而不是每次都由一个全新 IP 发起。这直接决定了 TOP 攻击者排行、
# 攻击链桑基图与地理热力图是否有真实的"聚集感"。
BOTNET_POOL_SIZE = 120

# 攻击类型真实分布权重 —— 均匀 1/6 是"为了展示全部类型而平均分配"，
# 与真实观测不符。下表参考公开 DDoS 报告的经验分布。
ATTACK_TYPE_WEIGHTS = {
    "syn_flood":  45,   # 约 40-50%
    "udp_flood":  18,   # 约 15-20%
    "http_flood": 13,   # 约 10-15%
    "dns_amp":     7,   # 约 5-8%
    "slowloris":   5,   # 约 3-5%
    "icmp_flood":  3,   # 约 2-3%
    # 剩余权重自动分配给其它已定义类型（便于后续扩展新类型而不改这里）
}

# 攻击带宽长尾参数 —— 真实攻击量级是长尾分布（大量小攻击 + 少量超大攻击），
# 原实现的均匀分布 100~3000 Mbps 缺少这种特征。
# 采用对数正态分布：中位数约 180 Mbps，长尾可达数 Gbps。
ATTACK_BANDWIDTH = {
    "median_mbps": 180.0,   # 中位数
    "sigma": 1.15,          # 对数标准差，越大长尾越明显
    "min_mbps": 20.0,       # 下限
    "max_mbps": 6000.0,     # 上限（避免生成不合理的超大值）
}

# 流量基线（Mbps）—— 对一个演示站点而言，原 350 Mbps 明显偏高，
# 且会让"攻击峰值"相对基线不够突出。下调后攻击更容易形成可见的尖峰。
TRAFFIC_BASELINE_MBPS = 90

# 攻击类型定义 — 每种类型的展示名称、图标、主题色和风险等级
# 用于前端图表渲染和告警分级
ATTACK_TYPES = {
    "syn_flood":  {"name": "SYN Flood",  "icon": "🌊", "color": "#ff4444", "risk": "高危"},
    "udp_flood":  {"name": "UDP Flood",  "icon": "💥", "color": "#ff8800", "risk": "高危"},
    "http_flood": {"name": "HTTP Flood", "icon": "🌐", "color": "#ffbb00", "risk": "中危"},
    "dns_amp":    {"name": "DNS 放大",   "icon": "🔍", "color": "#cc44ff", "risk": "高危"},
    "slowloris":  {"name": "Slowloris",  "icon": "🐢", "color": "#44aaff", "risk": "中危"},
    "icmp_flood": {"name": "ICMP Flood", "icon": "📡", "color": "#ff6644", "risk": "中危"},
}


# ======================== 全球 IP 地理映射 ========================
# 模拟数据，用于攻击热力地图的地理位置可视化
# 结构：国家代码 → { 城市列表, 纬度范围, 经度范围 }
# 注意：这是模拟数据，生产环境应接入 GeoIP 数据库（如 MaxMind GeoLite2）

GEO_IP_MAP = {
    "US": {"cities": ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix",
                       "Philadelphia", "San Antonio", "San Diego", "Dallas", "San Jose"],
           "lat_range": (25, 48), "lng_range": (-125, -67)},
    "CN": {"cities": ["Beijing", "Shanghai", "Guangzhou", "Shenzhen", "Chengdu",
                       "Wuhan", "Nanjing", "Hangzhou", "Xian", "Chongqing"],
           "lat_range": (20, 50), "lng_range": (73, 135)},
    "RU": {"cities": ["Moscow", "St.Petersburg", "Novosibirsk", "Yekaterinburg", "Kazan"],
           "lat_range": (41, 70), "lng_range": (20, 170)},
    "BR": {"cities": ["Sao Paulo", "Rio", "Brasilia", "Salvador", "Fortaleza"],
           "lat_range": (-34, 5), "lng_range": (-75, -30)},
    "IN": {"cities": ["Mumbai", "Delhi", "Bangalore", "Hyderabad", "Chennai"],
           "lat_range": (6, 35), "lng_range": (68, 90)},
    "DE": {"cities": ["Berlin", "Frankfurt", "Munich", "Hamburg", "Dusseldorf"],
           "lat_range": (47, 55), "lng_range": (5, 16)},
    "GB": {"cities": ["London", "Manchester", "Birmingham", "Glasgow", "Leeds"],
           "lat_range": (50, 60), "lng_range": (-8, 2)},
    "JP": {"cities": ["Tokyo", "Osaka", "Nagoya", "Sapporo", "Fukuoka"],
           "lat_range": (30, 45), "lng_range": (128, 146)},
    "KR": {"cities": ["Seoul", "Busan", "Incheon", "Daegu", "Daejeon"],
           "lat_range": (33, 38), "lng_range": (124, 131)},
    "FR": {"cities": ["Paris", "Marseille", "Lyon", "Toulouse", "Nice"],
           "lat_range": (42, 51), "lng_range": (-5, 8)},
    "NL": {"cities": ["Amsterdam", "Rotterdam", "The Hague", "Utrecht", "Eindhoven"],
           "lat_range": (50.7, 53.5), "lng_range": (3.3, 7.2)},
    "CA": {"cities": ["Toronto", "Vancouver", "Montreal", "Calgary", "Ottawa"],
           "lat_range": (42, 70), "lng_range": (-140, -52)},
    "VN": {"cities": ["Hanoi", "Ho Chi Minh", "Da Nang", "Haiphong", "Can Tho"],
           "lat_range": (8, 23), "lng_range": (102, 110)},
    "UA": {"cities": ["Kyiv", "Kharkiv", "Odesa", "Dnipro", "Lviv"],
           "lat_range": (44, 52), "lng_range": (22, 40)},
}


# ======================== 防护节点配置 ========================
# 模拟 CDN/清洗中心的地理位置和清洗能力
# 在地图上展示为绿色盾牌锚点，攻击来源会自动关联到最近的防护节点
MITIGATION_NODES = [
    {"name": "北京清洗中心",   "lat": 39.9,  "lng": 116.4, "capacity": "2Tbps"},
    {"name": "上海清洗中心",   "lat": 31.2,  "lng": 121.5, "capacity": "1.8Tbps"},
    {"name": "广州清洗中心",   "lat": 23.1,  "lng": 113.3, "capacity": "1.5Tbps"},
    {"name": "成都清洗中心",   "lat": 30.6,  "lng": 104.1, "capacity": "1.2Tbps"},
    {"name": "香港清洗中心",   "lat": 22.3,  "lng": 114.2, "capacity": "1Tbps"},
    {"name": "新加坡节点",     "lat": 1.35,  "lng": 103.8, "capacity": "800Gbps"},
    {"name": "东京节点",       "lat": 35.7,  "lng": 139.7, "capacity": "800Gbps"},
    {"name": "法兰克福节点",   "lat": 50.1,  "lng": 8.68,  "capacity": "600Gbps"},
]


# ======================== 告警通知配置 ========================
# 通知系统的作用：补齐 SOC 闭环中"告警触达"这一环 ——
# 当没有人盯着大屏时，把高危告警推到值班人邮箱。
#
# 设计原则：
# 1. 通知决策在服务端（若由前端决定，刷新页面就会重复推送）
# 2. 投递异步化 + 超时 + 失败隔离（绝不影响告警生成主流程）
# 3. 全量留痕（成功 / 失败 / 被限流 都要落库，可审计）
#
# SMTP 敏感信息优先从环境变量读取，其次读数据库配置：
#   CYBERGUARD_SMTP_HOST / CYBERGUARD_SMTP_PORT / CYBERGUARD_SMTP_USER
#   CYBERGUARD_SMTP_PASS / CYBERGUARD_SMTP_FROM / CYBERGUARD_SMTP_TLS
NOTIFY_RULES = {
    # 最低通知风险等级：低于此等级不发送（高危 / 中危 / 低危）
    "min_risk": "高危",

    # 去重窗口（分钟）：同一来源 IP + 同一告警类型，在此窗口内只通知一次。
    # 攻击浪潮突袭期速率可达 70 个/分钟，不做去重会瞬间淹没收件箱。
    "dedup_minutes": 5,

    # 限流：每个渠道在窗口内最多投递多少封
    "rate_limit_window_minutes": 5,
    "rate_limit_max": 3,

    # 静默时段：非工作时间仅放行"静默期最低等级"以上的告警。
    # 依据：非工作时间的推送涉及员工休息权，真实企业普遍设置静默时段。
    # 留空字符串表示不启用静默时段。
    "quiet_hours": "22:00-08:00",
    "quiet_min_risk": "高危",

    # 聚合窗口（秒）：窗口内产生的多条告警合并为一封摘要邮件。
    # 这是对抗"告警疲劳"的关键手段 —— 把 N 封邮件压成 1 封。
    "aggregate_seconds": 12,
}

# 单封通知邮件最多列出多少条告警（超出部分只给计数）
NOTIFY_MAX_ALERTS_PER_MAIL = 20

# 投递超时（秒）—— SMTP 连接与发送的总超时
NOTIFY_SMTP_TIMEOUT = 10

# 本地存底目录：每封邮件同时落一份 .eml 文件。
# 用途：即使没有可用 SMTP 服务器（演示环境常见），也能用任意邮件客户端
# 打开该文件查看真实生成的邮件内容，从而验证"邮件确实真的生成了"，
# 而不是只写了一条"已发送"日志。这延续了本项目的数据透明原则。
NOTIFY_OUTBOX_DIR = "sent_emails"
