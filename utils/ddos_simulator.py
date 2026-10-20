"""
==============================================================================
  CyberGuard — DDoS 攻击流量模拟器
==============================================================================
  在内存中模拟真实的 DDoS 攻击场景，为前端可视化提供动态数据流。

  模拟的攻击类型（6 种）：
  ┌──────────────┬────────────────────────────────────────────┐
  │ SYN Flood    │ TCP 半连接洪水，消耗服务器连接表资源       │
  │ UDP Flood    │ UDP 大流量洪水，耗尽网络带宽               │
  │ HTTP Flood   │ HTTP 应用层洪水，耗尽 Web 服务器资源       │
  │ DNS 放大     │ 利用 DNS 反射放大攻击，流量可达数十倍      │
  │ Slowloris    │ 慢速 HTTP 攻击，保持大量半开连接           │
  │ ICMP Flood   │ ICMP 洪水（Ping Flood），消耗网络资源      │
  └──────────────┴────────────────────────────────────────────┘

  架构设计：
  - 纯内存状态机（无数据库依赖），存储在 _attack_state 字典中
  - 每个 simulate_tick() 调用代表一个时间片（约 1.5 秒真实时间）
  - 数据自动滚动清理：流量历史保留 60 点、攻击链 20 条、时间线 50 条
  - 攻击生成采用概率模型：每次 tick 有 25% 概率产生新攻击事件

  状态管理：
  - 全局变量 _attack_state 存储所有模拟数据（约 10 类数据结构）
  - simulate_tick(): 单次状态更新（生成流量、攻击事件、清理过期数据）
  - get_current_state(): 获取完整状态快照（供 API 和 WebSocket 使用）
  - reset_state(): 重置所有状态到初始值
==============================================================================
"""

import random
import datetime
import math
from collections import defaultdict, deque
from config import (
    GEO_IP_MAP, ATTACK_TYPES, MITIGATION_NODES,
    ATTACK_WAVE, BOTNET_POOL_SIZE, ATTACK_TYPE_WEIGHTS,
    ATTACK_BANDWIDTH, TRAFFIC_BASELINE_MBPS,
)


# ============================================================================
#                         全局模拟状态 — 所有模拟数据的容器
# ============================================================================

_attack_state = {
    # ---------- 当前活跃攻击列表 ----------
    # 每个元素为一个攻击事件字典，包含 id、类型、来源IP、带宽、状态等
    "current_attacks": [],

    # ---------- 流量历史时间序列 ----------
    # 每个元素为 {timestamp, traffic_mbps, packets_pps, connections, is_attack}
    # 保留最近 60 个数据点（约 90 秒的数据）
    "traffic_history": [],

    # ---------- TOP 攻击者统计 ----------
    # 字典结构：{ip: {count, bandwidth, types: set(), country, lat, lng}}
    # 按累计攻击带宽降序排列
    "top_attackers": defaultdict(
        lambda: {"count": 0, "bandwidth": 0, "types": set(), "country": "", "lat": 0, "lng": 0}
    ),

    # ---------- 攻击链事件 ----------
    # 每个攻击链包含：nodes（源IP→攻击类型→目标端口→防护节点→结果）、links（流向权重）、timeline（时间阶段）
    # 保留最近 20 条
    "attack_chain_events": [],

    # ---------- 地理攻击数据 ----------
    # 每个元素为 {lat, lng, country, city, type, bandwidth, count}
    # 用于热力地图的散点渲染，保留最近 100 条
    "geo_attacks": [],

    # ---------- 受影响目标聚合 ----------
    # 结构：{ "端口:80": {"port":80, "protocol":"TCP", "hits":n, "bandwidth":x,
    #                     "types": set(), "mitigated": n} }
    # 用途：真实 SOC 面板关心的不只是"谁在打"，还有"打的是我们的哪个服务"。
    # 这里按目标端口聚合，形成"受影响服务"视图（区别于按攻击源聚合的 TOP 攻击者）。
    "affected_targets": defaultdict(
        lambda: {"port": 0, "protocol": "", "service": "", "hits": 0,
                 "bandwidth": 0.0, "types": set(), "mitigated": 0}
    ),

    # ---------- 核心统计指标 ----------
    "stats": {
        "total_packets": 0,          # 累计数据包数
        "total_bandwidth_mbps": 0,   # 当前总带宽（近 5 点均值）
        "mitigated_count": 0,        # 已缓解的攻击数
        "active_connections": 0,     # 活跃连接数
        "protection_rate": 99.2,     # 防护成功率（%）
        # 正在清洗中的攻击数。原先由前端用 attacks*0.2 这个魔法数字伪造，
        # 现改为沙箱内按状态真实统计（见 simulate_tick 步骤3）。
        "cleaning_count": 0,
        "uptime_hours": 8760,        # 系统运行时长（小时）
        "last_24h_attacks": 0,       # 最近 24 小时攻击数
    },

    # ---------- 攻击类型计数器 ----------
    # defaultdict(int)，key 为攻击类型名称，value 为出现次数
    "attack_types_count": defaultdict(int),

    # ---------- 攻击浪潮状态 ----------
    # 四阶段状态机：calm → rise → surge → decay → calm
    # left 是当前阶段的剩余 tick 数，归零即切换到下一阶段。
    # 这是"攻击频率"的唯一控制量 —— 出攻击概率由当前阶段查表决定。
    "wave": {
        "phase": "calm",
        "left": 45,          # 启动后约 1 分钟进入第一次攀升，便于演示
        "waves": 0,          # 已完成的完整浪潮数
        "spawned": 0,        # 本轮浪潮已生成的攻击事件数
    },

    # ---------- 僵尸网络肉鸡池 ----------
    # 攻击源从固定池中抽取（允许重复），模拟真实僵尸网络
    # "同一批肉鸡在 C2 指挥下反复攻击"的特征。
    # 每次调用 reset_state() 重新生成一批，保证 IP 稳定可复现。
    "botnet": [],

    # ---------- 流量基线 ----------
    # 正常情况下的基础流量值，攻击流量在此基础上叠加
    "traffic_baseline_mbps": TRAFFIC_BASELINE_MBPS,

    # ---------- 最近 24 小时事件时间戳 ----------
    # 说明：原实现把 last_24h_attacks 赋值为 len(current_attacks)，
    # 字段名说"24 小时"，值是"当前活跃数"，名不副实。
    # 这里用有界队列记录每个攻击事件的时间戳，真正统计 24 小时窗口内的事件数。
    # 队列长度上限按突袭期峰值估算（约 70 个/分钟 x 60 分钟），避免无限增长。
    "attack_timestamps": deque(maxlen=20000),

    # ---------- 攻击事件时间线 ----------
    # 每个元素为 {time, type, source, status, bandwidth}
    # 保留最近 50 条
    "timeline": []
}


# ============================================================================
#                         常量定义
# ============================================================================

# 攻击状态 —— 由"是否已缓解"派生，不再单独维护一份状态表。
#
# 历史问题（已修复）：这里原先有一个 STATUSES = ["攻击中","已缓解","清洗中",
# "已拦截","检测中"] 的常量，但**从未被使用**，而且其中「已缓解」「清洗中」
# 永远不会真正出现在数据里（生成逻辑用的是另一套内联列表）。
# 两套词表并存，是「已拦截链数」统计口径对不上的根源。
# 现在只保留下面两份权威定义，生成与统计都以它们为准。

# 已缓解时的处置结果（加权抽样表：同一结果重复出现即代表权重）
MITIGATION_RESULTS_WEIGHTED = ["已拦截", "已拦截", "已拦截", "已清洗", "限速中"]

# 未缓解时仍处于进行中的状态
PENDING_STATUSES = ["攻击中", "检测中"]

# 攻击类型键列表
ATTACK_TYPE_KEYS = list(ATTACK_TYPES.keys())


def _build_type_weights():
    """按配置构造攻击类型的加权抽样表。

    设计说明：原实现用 random.choice(ATTACK_TYPE_KEYS) 均匀抽取，
    六类各占 1/6 —— 这是"为了把全部类型都展示出来"的均匀分配，
    与真实观测不符（真实中 SYN Flood 约占 40-50%，ICMP Flood 仅 2-3%）。
    未被显式配置的类型自动获得一个保底权重，便于后续扩展新类型。
    """
    keys, weights = [], []
    for k in ATTACK_TYPE_KEYS:
        keys.append(k)
        weights.append(ATTACK_TYPE_WEIGHTS.get(k, 4))
    return keys, weights


_ATTACK_KEYS, _ATTACK_WEIGHTS = _build_type_weights()


def _build_botnet_pool(size=None):
    """生成僵尸网络肉鸡池（使用 RFC 5737 文档保留段，不指向真实资产）。

    池中每个 IP 带固定地理位置，因此同一肉鸡在多轮攻击中
    会稳定出现在同一国家/城市 —— 这正是地理热力图与 TOP 攻击者
    排行呈现"聚集感"的来源。
    """
    n = size or BOTNET_POOL_SIZE
    pool, seen = [], set()
    while len(pool) < n:
        info = _random_geo_ip()
        if info["ip"] in seen:
            continue
        seen.add(info["ip"])
        pool.append(info)
    return pool


def _sample_bandwidth():
    """按对数正态分布抽攻击带宽（长尾分布）。

    原实现是 random.uniform(100, 3000)，均匀分布缺少长尾特征：
    真实攻击量级是"大量小攻击 + 少量超大攻击"。
    这里用对数正态，中位数约 180 Mbps，长尾可到数 Gbps。
    """
    cfg = ATTACK_BANDWIDTH
    sigma = cfg["sigma"]
    median = cfg["median_mbps"]
    # 由中位数与 sigma 反推对数正态的 mu
    mu = math.log(median)
    bw = random.lognormvariate(mu, sigma)
    return max(cfg["min_mbps"], min(bw, cfg["max_mbps"]))

# 缓解结果选项 — 不同防护措施的效果
# ⚠ 这是"防护节点可能给出的处置动作"的全集，用于文案与图例；
#   具体某次攻击落到哪个结果，由上面的 MITIGATION_RESULTS_WEIGHTED 加权抽样。
MITIGATION_RESULTS = ["已拦截", "已清洗", "限速中", "已放行", "黑洞路由"]

# 目标服务池 —— 端口与协议必须配对，不能分别随机抽取。
#
# BUG 修复说明：
# 原实现把 TARGET_PORTS 和 PROTOCOLS 各自独立随机取值，
# 于是会生成"53 端口 + ICMP""3389 端口 + DNS"这类现实中不存在的组合。
# 一旦评委在"受影响服务"或攻击链详情里看到这种配对，整套数据的可信度就没了。
# 现改为从"真实存在的服务"列表中选取，(端口, 协议, 服务名) 三者绑定。
TARGET_SERVICES = [
    (80,    "HTTP",  "Web 服务"),
    (443,   "HTTPS", "TLS 服务"),
    (53,    "DNS",   "DNS 解析"),
    (22,    "SSH",   "SSH 管理"),
    (3306,  "MySQL", "数据库"),
    (8080,  "HTTP",  "备用 Web"),
    (8443,  "HTTPS", "备用 TLS"),
    (3389,  "RDP",   "远程桌面"),
    (25,    "SMTP",  "邮件服务"),
    (21,    "FTP",   "文件传输"),
]

# 兼容旧引用：仅端口列表与协议列表
TARGET_PORTS = [s[0] for s in TARGET_SERVICES]
PROTOCOLS = sorted({s[1] for s in TARGET_SERVICES})


# ============================================================================
#                         数据生成函数
# ============================================================================

def _random_geo_ip():
    """
    生成一个带地理信息的随机攻击 IP

    工作流程：
    1. 随机选择一个国家代码
    2. 从该国家的经纬度范围内随机生成坐标
    3. 随机选择一个城市
    4. 随机生成 IPv4 地址

    Returns:
        dict: {country, city, lat, lng, ip}
    """
    country_code = random.choice(list(GEO_IP_MAP.keys()))
    info = GEO_IP_MAP[country_code]
    lat = round(random.uniform(*info["lat_range"]), 1)
    lng = round(random.uniform(*info["lng_range"]), 1)
    city = random.choice(info["cities"])
    return {
        "country": country_code,
        "city": city,
        "lat": lat,
        "lng": lng,
        "ip": (
            f"{random.randint(1, 223)}.{random.randint(0, 255)}."
            f"{random.randint(0, 255)}.{random.randint(0, 255)}"
        )
    }


def generate_traffic_burst():
    """
    生成一次流量脉冲数据点（模拟实时流量采样）

    流量模型：
    - 基线流量：350 Mbps（正常流量）
    - 随机噪声：高斯分布 N(0, 50)，模拟正常波动
    - 攻击峰值：15% 概率叠加 200-2000 Mbps 的攻击流量

    Returns:
        dict: {timestamp, traffic_mbps, packets_pps, connections, is_attack}
    """
    baseline = _attack_state["traffic_baseline_mbps"]

    # 高斯噪声模拟网络流量的自然波动
    noise = random.gauss(0, 50)

    # 15% 概率出现攻击流量峰值
    attack_spike = 0
    if random.random() < 0.15:
        attack_spike = random.uniform(200, 2000)

    traffic = max(0, baseline + noise + attack_spike)

    # 根据流量估算 PPS 和连接数（非精确映射，仅用于视觉效果）
    packets = int(traffic * random.uniform(800, 1200))
    connections = int(traffic * random.uniform(0.5, 2))

    return {
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
        "traffic_mbps": round(traffic, 1),
        "packets_pps": packets,
        "connections": connections,
        "is_attack": attack_spike > 0
    }


def generate_attack_event():
    """
    生成一个完整的 DDoS 攻击事件

    包含字段说明：
    - id:            攻击事件唯一标识（ATK-XXXXX）
    - type/type_name: 攻击类型键/显示名称
    - source_*:      攻击源的地理和网络信息
    - target_port:   目标端口
    - bandwidth_mbps: 攻击带宽
    - status:        当前状态（攻击中/已拦截/已清洗等）
    - mitigation_node: 负责防护的清洗中心
    - harm_score:    危害评分（1-10）

    Returns:
        dict: 完整的攻击事件字典
    """
    # 攻击类型按真实分布加权抽取（不再均匀 1/6）
    attack_type_key = random.choices(_ATTACK_KEYS, weights=_ATTACK_WEIGHTS, k=1)[0]
    attack_type = ATTACK_TYPES[attack_type_key]
    # 攻击源从固定肉鸡池抽取（可重复）—— 体现僵尸网络复用特征
    geo = random.choice(_attack_state["botnet"]) if _attack_state["botnet"] else _random_geo_ip()
    # 端口 / 协议 / 服务名三者绑定选取，避免出现"53 端口 + ICMP"这类非法组合
    target_port, protocol, service_name = random.choice(TARGET_SERVICES)
    mitigation_node = random.choice(MITIGATION_NODES)

    # 攻击带宽按长尾分布抽样（替代原均匀 100~3000）
    bandwidth = _sample_bandwidth()
    packets = int(bandwidth * random.uniform(500, 1500))

    # 攻击开始时间：最近 5 分钟内的随机时间
    start_time = datetime.datetime.now() - datetime.timedelta(
        seconds=random.randint(0, 300)
    )

    # 85% 概率攻击已被缓解
    mitigated = random.random() < 0.85
    if mitigated:
        result = random.choice(MITIGATION_RESULTS_WEIGHTED)
    else:
        result = random.choice(PENDING_STATUSES)

    return {
        "id": f"ATK-{random.randint(10000, 99999)}",
        "type": attack_type_key,
        "type_name": attack_type["name"],
        "risk": attack_type["risk"],
        "source_ip": geo["ip"],
        "source_country": geo["country"],
        "source_city": geo["city"],
        "source_lat": geo["lat"],
        "source_lng": geo["lng"],
        "target_port": target_port,
        "protocol": protocol,
        "service": service_name,
        "bandwidth_mbps": round(bandwidth, 1),
        "packets_pps": packets,
        "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": result,
        # 是否已被缓解（布尔）。
        # 为什么单独给出这一个字段：
        #   status 是给人看的中文措辞，"已拦截 / 已清洗 / 限速中" 都属于"已缓解"，
        #   而前端原先靠 `status.includes('已拦截') || status.includes('已清洗')`
        #   判断，漏掉了"限速中" —— 导致「已拦截链数」系统性少算。
        #   这里直接给出语义字段，前端不再靠中文子串猜。
        "mitigated": bool(mitigated),
        "mitigation_node": mitigation_node["name"],
        "mitigation_lat": mitigation_node["lat"],
        "mitigation_lng": mitigation_node["lng"],
        "duration_seconds": random.randint(30, 3600),
        "harm_score": round(random.uniform(1, 10), 1),
        # 存活计数：每 tick 自增，达到 ATTACK_WAVE["event_ttl_ticks"] 后
        # 从活跃列表淘汰。没有这个字段时，"攻击中/检测中"的事件会永久堆积，
        # 突袭期密集生成会让活跃攻击数越滚越大而失真。
        "age_ticks": 0,
        # 该肉鸡在本轮浪潮内第几次发起攻击（1 表示首次），
        # 用于前端展示"同一肉鸡重复攻击"的僵尸网络特征。
        "botnet_hits": 1,
    }


def generate_attack_chain(attack_event):
    """
    根据攻击事件生成攻击链路数据（桑基图输入）

    链路结构（5 个节点 → 4 条链接）：
    源IP → 攻击类型 → 目标端口 → 防护节点 → 缓解结果
    每条链接的 value 从攻击带宽递减，模拟流量在链路中的损耗

    附加时间线：5 个关键阶段的时间点
    攻击发起 → 流量峰值 → 检测识别 → 流量牵引 → 最终状态

    Args:
        attack_event: generate_attack_event() 生成的攻击事件

    Returns:
        dict: {nodes, links, timeline}，符合 ECharts 桑基图数据格式
    """
    duration = attack_event["duration_seconds"]
    now = datetime.datetime.now()

    return {
        "attack_id": attack_event["id"],
        # 该链路是否已被缓解 —— 前端「已拦截链数」按此字段计数。
        # 不要再用 status 的中文措辞判断："已拦截 / 已清洗 / 限速中" 三者
        # 同属已缓解，靠子串匹配会漏掉「限速中」。
        "mitigated": bool(attack_event.get("mitigated")),
        # 5 个节点：源 → 攻击 → 目标 → 防护 → 结果
        "nodes": [
            {"name": f"源IP\n{attack_event['source_ip']}",
             "category": "source",
             "lat": attack_event["source_lat"],
             "lng": attack_event["source_lng"]},
            {"name": f"{attack_event['type_name']}\n攻击流量",
             "category": "attack",
             "value": attack_event["bandwidth_mbps"]},
            {"name": f"端口{attack_event['target_port']}\n{attack_event['protocol']}",
             "category": "target"},
            {"name": attack_event["mitigation_node"],
             "category": "mitigation"},
            {"name": attack_event["status"],
             "category": "result"},
        ],
        # 4 条链接：流量从大到小递减，模拟清洗效果
        "links": [
            {"source": f"源IP\n{attack_event['source_ip']}",
             "target": f"{attack_event['type_name']}\n攻击流量",
             "value": attack_event["bandwidth_mbps"]},
            {"source": f"{attack_event['type_name']}\n攻击流量",
             "target": f"端口{attack_event['target_port']}\n{attack_event['protocol']}",
             "value": attack_event["bandwidth_mbps"] * 0.9},
            {"source": f"端口{attack_event['target_port']}\n{attack_event['protocol']}",
             "target": attack_event["mitigation_node"],
             "value": attack_event["bandwidth_mbps"] * 0.85},
            {"source": attack_event["mitigation_node"],
             "target": attack_event["status"],
             "value": attack_event["bandwidth_mbps"] * 0.1},
        ],
        # 攻击时间线：5 个关键阶段
        "timeline": [
            {"stage": "攻击发起", "time": (now - datetime.timedelta(seconds=duration)).strftime("%H:%M:%S")},
            {"stage": "流量峰值", "time": (now - datetime.timedelta(seconds=duration * 0.3)).strftime("%H:%M:%S")},
            {"stage": "检测识别", "time": (now - datetime.timedelta(seconds=duration * 0.5)).strftime("%H:%M:%S")},
            {"stage": "流量牵引", "time": (now - datetime.timedelta(seconds=duration * 0.7)).strftime("%H:%M:%S")},
            {"stage": attack_event["status"], "time": now.strftime("%H:%M:%S")},
        ]
    }


# ============================================================================
#                         状态管理函数
# ============================================================================

# ============================================================================
#                         攻击浪潮状态机
# ============================================================================

def _triangular_ticks(phase):
    """按三角分布抽取某阶段的持续 tick 数。

    众数刻意偏向区间下沿（ratio 字段），使"短周期多、长周期少"，
    符合真实攻击间隔的长尾特征；若用均匀分布会出现
    "每隔固定时间准来一波"的机械感。
    """
    low, high, ratio = ATTACK_WAVE["durations"][phase]
    return int(random.triangular(low, high, low + (high - low) * ratio))


def _advance_wave():
    """推进浪潮状态机：倒计时归零则切到下一阶段。

    转移路径是确定的（calm→rise→surge→decay→calm），
    随机性只体现在"每个阶段持续多久"以及"每 tick 是否命中出攻击"上。
    """
    w = _attack_state["wave"]
    w["left"] -= 1
    if w["left"] > 0:
        return w["phase"]

    nxt = {"calm": "rise", "rise": "surge", "surge": "decay", "decay": "calm"}
    w["phase"] = nxt.get(w["phase"], "calm")
    w["left"] = _triangular_ticks(w["phase"])
    if w["phase"] == "calm":
        # 回到平静期表示一轮完整浪潮结束
        w["waves"] += 1
        w["spawned"] = 0
    return w["phase"]


def trigger_wave(force_surge=True):
    """手动引爆一波攻击（供演示使用）。

    设计意图：浪潮结构让"平静期"成为常态，但答辩现场不能干等。
    该函数把状态机直接推进到突袭期，既保留真实的时间结构，
    又允许演示者主动制造攻击高峰。
    """
    w = _attack_state["wave"]
    w["phase"] = "surge" if force_surge else "rise"
    w["left"] = _triangular_ticks(w["phase"])
    w["spawned"] = 0
    return {"phase": w["phase"], "label": wave_label(w["phase"]), "left": w["left"]}


def wave_label(phase=None):
    """阶段的中文展示名。"""
    p = phase or _attack_state["wave"]["phase"]
    return ATTACK_WAVE["labels"].get(p, p)


def get_wave_status():
    """返回当前浪潮状态的快照，供 API 与前端徽章使用。"""
    w = _attack_state["wave"]
    prof = ATTACK_WAVE["profiles"].get(w["phase"], (0, 0, 0))
    return {
        "phase": w["phase"],
        "label": wave_label(),
        "left_ticks": w["left"],
        "left_seconds": round(w["left"] * 1.5, 1),   # 1 tick ≈ 1.5 秒
        "waves": w["waves"],
        "spawned": w["spawned"],
        "rate_per_min": round(prof[0] * (prof[1] + prof[2]) / 2 / 1.5 * 60, 1),
        "botnet_size": len(_attack_state["botnet"]),
    }


def _retire_attacks():
    """淘汰过期攻击事件。

    BUG 修复说明：原实现的清理条件是
        status in ("攻击中","检测中")  → 永不清理
        或 (now - start_time).seconds < 3600
    即"未结束的攻击永远不会被移除"。在恒定速率下影响不明显，
    但引入浪潮后，突袭期会密集生成事件，未结束的事件持续堆积，
    "活跃攻击"数会越滚越大直到失去意义。
    现改为按 age_ticks 淘汰，让列表长度主要由时间窗决定而非状态决定。
    """
    ttl = ATTACK_WAVE["event_ttl_ticks"]
    kept = []
    for a in _attack_state["current_attacks"]:
        a["age_ticks"] = a.get("age_ticks", 0) + 1
        if a["age_ticks"] < ttl:
            kept.append(a)
    _attack_state["current_attacks"] = kept


# 模块加载时先生成一批肉鸡，保证首个 tick 就有稳定的攻击源池
_attack_state["botnet"] = _build_botnet_pool()


def simulate_tick():
    """
    每个时间片执行一次，更新所有模拟状态

    这是模拟器的核心函数，在后台线程中每 1.5 秒调用一次。

    执行流程：
    1. 生成流量数据点 → 追加到 traffic_history
    2. 以 25% 概率生成 1-3 个新攻击事件
    3. 对每个新攻击生成攻击链、更新 TOP 攻击者、地理数据、攻击类型计数、时间线
    4. 重新计算核心统计指标（带宽、连接数、防护率、系统负载）
    5. 清理过期数据（攻击列表、攻击链、时间线、地理数据）
    """
    now = datetime.datetime.now()

    # ===== 步骤1：生成流量数据点 =====
    traffic_point = generate_traffic_burst()
    _attack_state["traffic_history"].append(traffic_point)

    # 流量历史窗口：60 → 240 点（约 6 分钟）
    # 浪潮一轮 4~7 分钟，窗口太短会看不到"平静→突袭"的完整曲线形态。
    if len(_attack_state["traffic_history"]) > 240:
        _attack_state["traffic_history"] = _attack_state["traffic_history"][-240:]

    # ===== 步骤2：按当前浪潮阶段生成新攻击事件 =====
    # 原实现是固定的 25% 概率出 1~3 个 —— 恒定速率的泊松过程，
    # 无论观察 10 秒还是 10 分钟攻击速率都一样，与真实的"事件型 DDoS"不符。
    # 现改为：先推进状态机，再按当前阶段的速率剖面查表决定是否出攻击。
    phase = _advance_wave()
    prob, lo, hi = ATTACK_WAVE["profiles"].get(phase, (0.02, 1, 1))
    if random.random() < prob:
        num_attacks = random.randint(lo, hi)
        _attack_state["wave"]["spawned"] += num_attacks
        for _ in range(num_attacks):
            event = generate_attack_event()
            _attack_state["current_attacks"].append(event)

            # 生成攻击链路数据
            chain = generate_attack_chain(event)
            _attack_state["attack_chain_events"].append(chain)

            # 更新 TOP 攻击者统计 — 按 IP 聚合
            attacker = _attack_state["top_attackers"][event["source_ip"]]
            attacker["count"] += 1
            # 记录该肉鸡的复用次数，体现僵尸网络"同一批 IP 反复攻击"的特征
            event["botnet_hits"] = attacker["count"]
            attacker["bandwidth"] += event["bandwidth_mbps"]
            attacker["types"].add(event["type_name"])
            attacker["country"] = event["source_country"]
            attacker["lat"] = event["source_lat"]
            attacker["lng"] = event["source_lng"]

            # 更新地理攻击数据（用于热力地图）
            _attack_state["geo_attacks"].append({
                "lat": event["source_lat"],
                "lng": event["source_lng"],
                "country": event["source_country"],
                "city": event["source_city"],
                "type": event["type_name"],
                "bandwidth": event["bandwidth_mbps"],
                "count": 1
            })

            # 更新攻击类型计数
            _attack_state["attack_types_count"][event["type_name"]] += 1

            # 更新「受影响服务」聚合 —— 按目标端口统计
            tgt = _attack_state["affected_targets"][f"端口:{event['target_port']}"]
            tgt["port"] = event["target_port"]
            tgt["protocol"] = event["protocol"]
            tgt["service"] = event.get("service", "")
            tgt["hits"] += 1
            tgt["bandwidth"] += event["bandwidth_mbps"]
            tgt["types"].add(event["type_name"])
            if event["status"] in ("已拦截", "已清洗", "限速中"):
                tgt["mitigated"] += 1

            # 记录事件时间戳（用于统计最近 24 小时攻击数）
            _attack_state["attack_timestamps"].append(now)

            # 追加攻击事件时间线
            _attack_state["timeline"].append({
                "time": now.strftime("%H:%M:%S"),
                "type": event["type_name"],
                "source": event["source_ip"],
                "status": event["status"],
                "bandwidth": event["bandwidth_mbps"]
            })

    # ===== 步骤3：更新核心统计 =====
    # 当前带宽 = 最近 5 个流量点的均值
    recent = _attack_state["traffic_history"][-5:]
    total_bw = sum(tp["traffic_mbps"] for tp in recent) / min(5, len(recent))
    _attack_state["stats"]["total_bandwidth_mbps"] = round(total_bw, 1)
    _attack_state["stats"]["total_packets"] += traffic_point["packets_pps"]
    _attack_state["stats"]["active_connections"] = traffic_point["connections"]
    _attack_state["stats"]["mitigated_count"] = sum(
        1 for a in _attack_state["current_attacks"]
        if a["status"] in ["已拦截", "已清洗", "限速中"]
    )
    # 新增：正在清洗中的攻击数（真实统计，替代前端原先的 attacks*0.2 魔法数字）
    _attack_state["stats"]["cleaning_count"] = sum(
        1 for a in _attack_state["current_attacks"]
        if a["status"] == "清洗中"
    )
    # 系统负载字段已移除：原实现为 "30 + 沙箱带宽/20"，属于编造值。
    # 主机真实负载现由 utils/host_metrics.py 通过 psutil 采集，
    # 在 state["host"] 中单独提供，且标注为「实时采集」。
    #
    # last_24h_attacks 改为真实统计：从时间戳队列中筛出 24 小时内的记录。
    _cutoff = now - datetime.timedelta(hours=24)
    _ts = _attack_state["attack_timestamps"]
    while _ts and _ts[0] < _cutoff:
        _ts.popleft()                     # 淘汰窗口外的旧记录
    _attack_state["stats"]["last_24h_attacks"] = len(_ts)

    # 防护成功率 = 已缓解数 / 总数
    if _attack_state["current_attacks"]:
        total_all = len(_attack_state["current_attacks"])
        mitigated = _attack_state["stats"]["mitigated_count"]
        _attack_state["stats"]["protection_rate"] = round(
            (mitigated / total_all) * 100, 1
        ) if total_all > 0 else 100.0

    # ===== 步骤4：清理过期数据 =====
    # 按 age_ticks 淘汰（替代原先"未结束就永不清理"的逻辑）
    _retire_attacks()

    # 限制各数据结构的最大长度
    # 注意：窗口大小必须与浪潮节奏匹配。突袭期速率可达 68 个/分钟，
    # 若攻击链只保留 20 条，桑基图窗口仅够覆盖约 18 秒，会剧烈跳动；
    # 扩大后能让"一波攻击的完整形态"留在画面上。
    if len(_attack_state["attack_chain_events"]) > 60:
        _attack_state["attack_chain_events"] = _attack_state["attack_chain_events"][-60:]

    if len(_attack_state["timeline"]) > 120:
        _attack_state["timeline"] = _attack_state["timeline"][-120:]

    if len(_attack_state["geo_attacks"]) > 300:
        _attack_state["geo_attacks"] = _attack_state["geo_attacks"][-300:]


def get_current_state():
    """
    获取当前完整的模拟状态快照

    在返回前对原始数据进行聚合和排序处理：
    - 地理数据：按经纬度聚合（同一位置的多次攻击合并统计）
    - TOP 攻击者：按累计带宽降序排列，取前 10
    - 流量/攻击链/时间线：截取最近 N 条

    Returns:
        dict: 包含所有前端可视化所需的完整状态数据
    """
    # 聚合地理数据 — 同一经纬度的攻击合并统计
    geo_aggregated = defaultdict(
        lambda: {"count": 0, "bandwidth": 0, "types": set()}
    )
    for g in _attack_state["geo_attacks"]:
        key = f"{g['lat']},{g['lng']}"
        geo_aggregated[key]["count"] += 1
        geo_aggregated[key]["bandwidth"] += g["bandwidth"]
        geo_aggregated[key]["types"].add(g["type"])
        geo_aggregated[key]["lat"] = g["lat"]
        geo_aggregated[key]["lng"] = g["lng"]
        geo_aggregated[key]["country"] = g["country"]
        geo_aggregated[key]["city"] = g["city"]

    geo_data = []
    for key, val in geo_aggregated.items():
        geo_data.append({
            "lat": val["lat"],
            "lng": val["lng"],
            "country": val["country"],
            "city": val["city"],
            "count": val["count"],
            "bandwidth": round(val["bandwidth"], 1),
            "types": list(val["types"])
        })

    # TOP10 攻击者 — 按累计攻击带宽降序排列
    top_attackers = sorted(
        [
            {"ip": ip, **data, "types": list(data["types"])}
            for ip, data in _attack_state["top_attackers"].items()
        ],
        key=lambda x: x["bandwidth"],
        reverse=True
    )[:10]

    # 受影响服务 —— 按目标端口聚合，命中次数降序
    # 这是真实 SOC 面板的核心视图之一："攻击打的是我们哪个服务"
    affected_targets = sorted(
        [
            {
                "key": k,
                "port": v["port"],
                "protocol": v["protocol"],
                "service": v["service"],
                "hits": v["hits"],
                "bandwidth": round(v["bandwidth"], 1),
                "mitigated": v["mitigated"],
                "types": sorted(v["types"]),
                "block_rate": round(v["mitigated"] / v["hits"] * 100, 1) if v["hits"] else 0.0,
            }
            for k, v in _attack_state["affected_targets"].items()
        ],
        key=lambda x: x["hits"],
        reverse=True
    )[:8]

    return {
        "stats": dict(_attack_state["stats"]),
        "traffic_history": _attack_state["traffic_history"][-60:],
        "current_attacks": _attack_state["current_attacks"][:40],
        "attack_chains": _attack_state["attack_chain_events"][:20],
        "geo_data": geo_data,
        "top_attackers": top_attackers,
        "affected_targets": affected_targets,
        "attack_types_count": dict(_attack_state["attack_types_count"]),
        "timeline": _attack_state["timeline"][-40:],
        "mitigation_nodes": MITIGATION_NODES,
        "attack_types": ATTACK_TYPES,
        "wave": get_wave_status(),
    }


def reset_state():
    """
    重置模拟状态到初始值

    清空所有攻击数据、流量历史、统计指标等。
    用于演示"重置模拟"场景，展示系统从零开始的初始化过程。

    Returns:
        dict: 操作结果状态
    """
    global _attack_state
    _attack_state = {
        "current_attacks": [],
        "traffic_history": [],
        "top_attackers": defaultdict(
            lambda: {"count": 0, "bandwidth": 0, "types": set(), "country": "", "lat": 0, "lng": 0}
        ),
        "attack_chain_events": [],
        "geo_attacks": [],
        "affected_targets": defaultdict(
            lambda: {"port": 0, "protocol": "", "service": "", "hits": 0,
                     "bandwidth": 0.0, "types": set(), "mitigated": 0}
        ),
        "stats": {
            "total_packets": 0,
            "total_bandwidth_mbps": 0,
            "mitigated_count": 0,
            "active_connections": 0,
            "protection_rate": 99.2,
            "cleaning_count": 0,
            "uptime_hours": 8760,
            "last_24h_attacks": 0,
        },
        "wave": {"phase": "calm", "left": 45, "waves": 0, "spawned": 0},
        "botnet": _build_botnet_pool(),
        "attack_timestamps": deque(maxlen=20000),
        "attack_types_count": defaultdict(int),
        "traffic_baseline_mbps": TRAFFIC_BASELINE_MBPS,
        "timeline": []
    }
    return {"status": "success", "message": "模拟状态已重置"}
