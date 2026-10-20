"""
==============================================================================
  CyberGuard — 模拟登录日志生成器
==============================================================================
  用于生成演示用的登录日志数据，包含正常日志和攻击日志两类。

  生成策略：
  ┌──────────────────────────────────────────────────────────────┐
  │ 正常日志（800条）：                                          │
  │   随机 IP、随机用户名、70% 成功率、24 小时内均匀分布         │
  │   模拟正常的用户登录行为                                     │
  ├──────────────────────────────────────────────────────────────┤
  │ 攻击日志（200条）：                                          │
  │   5 个攻击 IP，每个 15 次高频失败（间隔 10 秒）              │
  │   1 个特殊 IP，25 次失败 + 1 次成功（用于规则3测试）         │
  │   模拟各种暴力破解攻击模式                                   │
  └──────────────────────────────────────────────────────────────┘

  设计目的：
  - 为检测引擎提供可复现的测试数据
  - 答辩时快速演示各种检测规则的触发效果
  - 无需外部数据源即可展示完整功能
==============================================================================
"""

import random
import datetime
from utils.db_helper import insert_login_log
from config import COMMON_WEAK_PASSWORDS

# IP 前缀池 — 用于生成多样化的 IP 地址
# 包含内网段（用于模拟内部攻击）和公网段（用于模拟外部攻击）
IP_PREFIXES = [
    "192.168.",      # 内网 C 类
    "10.0.",         # 内网 A 类
    "172.16.",       # 内网 B 类
    "203.0.113.",    # 文档保留段
    "198.51.100.",   # 文档保留段
    "104.16.",       # Cloudflare 段
    "172.67.",       # Cloudflare 段
    "108.162."       # Cloudflare 段
]

# 口令样本池 —— 用于复现字典攻击（规则④）
#
# 说明：这里的口令是公开的常见弱口令样本，仅用于演示"攻击者拿弱口令字典试探"这一场景。
# 本系统不采集、不存储任何真实用户凭证。
#
# 重要：样本池**直接取自 config.COMMON_WEAK_PASSWORDS**，而不是另建一份列表。
# 原因：检测规则④只把"弱密码表内的口令"计入种类数，若生成器使用了一份包含
# 表外口令的自建列表，随机抽到表外口令时不会计数 —— 会出现"规则④静默不触发"
# 这种无报错的隐蔽缺陷。二者共用同一数据源即可彻底避免口径脱节。
WEAK_PASSWORD_SAMPLES = sorted(COMMON_WEAK_PASSWORDS)

# 常见用户名池 — 模拟真实登录场景的用户名分布
USERNAMES = [
    "admin", "root", "user", "guest", "test",
    "admin123", "administrator", "ubuntu", "centos", "nginx"
]

# User-Agent 池 — 模拟不同客户端环境
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "curl/7.68.0",                   # 命令行工具 — 常见于自动化攻击
    "python-requests/2.31.0"         # Python 脚本 — 常见于自动化攻击
]


def generate_random_ip():
    """
    生成一个随机 IPv4 地址（保证恰好 4 段）

    实现思路：
    1. 从 IP_PREFIXES 中随机选择一个前缀（2 段如 "10." 或 3 段如 "192.0.2."）
    2. 补足到 4 段，每段取值 1-254（避开 0/255 的特殊含义）

    BUG 修复说明：
    原实现用 prefix.rstrip('.').split('.') 统计已有段数，但对于
    "192.0.2." 这类以点结尾的前缀，rstrip('.') 得到 "192.0.2"，
    split('.') 仍得到 4 个元素（最后一个是空串），于是 need_parts 被算成 0，
    补 1 段后拼出 **5 段**的非法 IP，例如 "203.0.113.32.114"。
    这里改为只统计非空段，并显式断言最终必须是 4 段。

    Returns:
        str: 完整 IPv4 地址，格式如 "192.0.2.100"
    """
    prefix = random.choice(IP_PREFIXES)
    existing_parts = [p for p in prefix.split('.') if p]   # 只统计非空段
    need_parts = max(0, 4 - len(existing_parts))
    octets = existing_parts + [str(random.randint(1, 254)) for _ in range(need_parts)]
    ip = '.'.join(octets)
    assert len(ip.split('.')) == 4, f'非法 IPv4: {ip}'
    return ip


def _normal_client_ips(count=120):
    """
    构造一组"正常客户端"IP 池。

    设计原因（重要）：
    原实现让 800 条正常日志各自使用**互不相同**的随机 IP，
    而演示用户名只有 10 个通用名（admin/root/test…）。这样一来，
    每个通用用户名都会被上百个不同 IP "尝试"过，直接命中规则2
    「账号多 IP 攻击」的判定条件（不同 IP 数 ≥ 8），导致系统把
    整个 IP 池判定为撞库攻击并连锁封禁——实测 872 条封禁中 843 条
    （96.7%）由此产生，属于典型的"高误报"缺陷。

    修正思路：让正常用户拥有**稳定的客户端 IP**（办公网/家庭宽带场景），
    即同一用户名基本只从少量固定 IP 登录。真实世界里同一账号从
    上百个 IP 登录本身就是异常信号，原数据是不合理的。
    """
    pool = []
    seen = set()
    while len(pool) < count:
        # 使用文档保留段（RFC 5737）与私网段（RFC 1918），不指向真实资产
        block = random.choice(["192.0.2", "198.51.100", "203.0.113", "10", "172.16"])
        # 统一按"非空段"补齐到 4 段，避免拼出 5 段非法 IP
        parts = [p for p in block.split('.') if p]
        parts += [str(random.randint(1, 254)) for _ in range(4 - len(parts))]
        ip = '.'.join(parts)
        if ip in seen:
            continue
        seen.add(ip)
        pool.append(ip)
    return pool


def generate_mock_logs(total_count=1000, with_attacks=True):
    """
    生成模拟登录日志（800 正常 + 攻击样本）

    生成流程：
    1. 以当前时间前 24 小时为起点（base_time）
    2. 800 条正常日志：从 120 个固定客户端 IP 中选取，24 小时内均匀分布，
       70% 成功率 —— 保证每个 IP 的失败次数远低于规则1阈值，不产生误报
    3. 攻击日志：5 个攻击 IP，每个 15 次高频失败（间隔 10 秒）→ 触发规则1
    4. 攻击日志：1 个攻击 IP，25 次失败 + 1 次成功 → 触发规则3

    正常 IP 与攻击 IP 使用**互不相交**的生成方式，避免演示时出现
    "正常用户被封禁"的连锁误报。

    Args:
        total_count: 期望生成的日志总条数（正常日志按此数量级生成）
        with_attacks: 是否附带攻击样本（默认 True；关掉可单独演示"干净基线"）
    """
    # 基准时间：24 小时前
    base_time = datetime.datetime.now() - datetime.timedelta(hours=24)

    # ======================== 正常日志 ========================
    # 稳定的客户端 IP 池 + 稳定的用户名，模拟真实办公/家庭登录行为
    client_ips = _normal_client_ips(120)
    # 用户名与客户端 IP 建立稳定绑定，进一步降低"账号多 IP"误判
    personas = [(random.choice(USERNAMES), ip) for ip in client_ips]
    normal_count = max(1, int(total_count * 0.8))

    # 每个客户端分配一个固定时段，并在时段内保持最小间隔。
    #
    # 为什么必须这样做（重要）：
    # 原实现让正常日志在 24 小时内**完全随机**分布，于是单个客户端一天会
    # 产生十几条登录、其中数条失败，并且失败可能偶然挤在几分钟内 ——
    # 直接命中规则①（5 分钟内失败 ≥10 次）。实测中确实出现了正常客户端
    # 被封禁的情况（同一 IP 有成功登录记录，却被判为高频失败）。
    # 真实世界的登录行为有节律：集中在工作时段，且不会秒级连发。
    # 这里用"专属时段 + 最小间隔"把正常流量塑造成合理形态，
    # 从而让 5 条规则只在真实攻击样本上触发，而不是在正常用户身上。
    per_client = max(1, normal_count // len(client_ips))
    # 最短间隔（秒）：9 次失败需 5 分钟才触发规则①，90 秒间隔可确保
    # 正常客户端在任何 5 分钟窗口内最多 4 次失败，留有充分余量
    min_gap = 90

    print("正在生成 {} 条正常日志（{} 个稳定客户端 IP，平均 {} 次/客户端）...".format(
        normal_count, len(client_ips), per_client))

    for username, ip in personas:
        # 每个客户端一个固定的活跃时段（2 小时内），起始时刻在其工作时段内随机
        slot_start = base_time + datetime.timedelta(minutes=random.randint(0, 1320))
        for k in range(per_client):
            log_time = slot_start + datetime.timedelta(
                seconds=k * (min_gap + random.randint(0, 240)))
            # 失败集中度控制：连续失败少于规则①阈值(10)，
            # 保证正常客户端不会被高频失败规则命中
            success = random.random() > 0.3      # 70% 成功率
            # 正常用户不记录口令（真实系统同样没有理由记录合法凭证，
            # 也符合数据最小采集原则）—— 该列留 NULL。
            insert_login_log(
                log_time.strftime("%Y-%m-%d %H:%M:%S"),
                ip, username, random.choice(USER_AGENTS), success,
                attempted_password=None
            )

    if not with_attacks:
        print("模拟日志生成完成（未附带攻击样本）！")
        return

    # ======================== 攻击样本的时间基准 ========================
    # 关键：攻击样本必须落在各自检测规则的时间窗内，否则规则取不到数据。
    # 各规则窗口：规则① 5 分钟 / 规则② 10 分钟 / 规则③ 15 分钟。
    # 因此样本不能像正常日志那样随机铺在 24 小时里 —— 那样它们会落在
    # "2~24 小时前"，被窗口过滤掉，规则表现为"随机触发"甚至"永不触发"。
    #
    # 下面为每组样本单独指定距现在的偏移（分钟），并使各组互相分离：
    #   规则① 末尾       -> now - 3 分钟   （落在 5 分钟窗内）
    #   规则②（撞库）    -> now - 9 分钟   （落在 10 分钟窗内，且在规则①窗之外）
    #   规则③（得手）    -> now - 20 分钟  （失败+成功同处 15 分钟窗内）
    #   规则④（字典）    -> now - 40 分钟  （与其它组分离）
    def _at(minutes_ago):
        """返回距当前时间指定分钟数的时间点。"""
        return datetime.datetime.now() - datetime.timedelta(minutes=minutes_ago)

    # ======================== 攻击样本：规则1 ========================
    # 5 个独立攻击 IP，每个 15 次高频失败（10 秒间隔 → 140 秒内完成）
    # 触发条件：5 分钟窗口内失败 ≥ 10 次
    print("正在生成规则1测试数据：5 个攻击 IP 各 15 次高频失败...")
    attack_ips = [generate_random_ip() for _ in range(5)]
    for ip in attack_ips:
        # 该组共 140 秒，令其末尾落在 now-3 分钟，则整组位于 5 分钟窗内
        attack_time = _at(3 + 140 / 60.0)
        # 真实暴力破解工具通常直接跑弱口令字典。给每组攻击分配一个
        # 较小的口令样本集（少于规则④的 5 种阈值），使其触发规则①
        # 而**不**触发规则④ —— 这样两条规则的演示效果可以清晰区分。
        auth_passwords = random.sample(WEAK_PASSWORD_SAMPLES, 3)
        for i in range(15):
            log_time = attack_time + datetime.timedelta(seconds=i * 10)
            insert_login_log(
                log_time.strftime("%Y-%m-%d %H:%M:%S"),
                ip, random.choice(USERNAMES), random.choice(USER_AGENTS), False,
                attempted_password=auth_passwords[i % len(auth_passwords)]
            )

    # ======================== 攻击样本：规则3 ========================
    # 模拟"暴力破解得手"：短窗口内高频失败 + 1 次成功
    #
    # BUG 修复说明（原数据永远无法触发规则3）：
    # 规则3 判定条件是「15 分钟窗口内失败 ≥ 20 次且成功 ≤ 2 次」，
    # 而原实现按"间隔 2 分钟 × 25 次"生成，总跨度 48 分钟，
    # 任意 15 分钟窗口内最多只有约 8 次失败，永远达不到阈值 20，
    # 导致这条最高危规则在演示中从未被触发过。
    # 现改为间隔 30 秒 × 25 次（总跨度 12 分钟），窗口内可达 25 次，稳定触发。
    target_ip = generate_random_ip()
    print(f"正在生成规则3测试数据：IP {target_ip} 12分钟内失败25次，随后成功1次")
    # 该组跨度 25x30 秒 = 12.5 分钟，令其末尾落在 now-6 分钟，
    # 则整组（含紧随其后的那次成功）位于规则③的 15 分钟窗内
    start_time = _at(6 + 25 * 30 / 60.0)
    breach_passwords = random.sample(WEAK_PASSWORD_SAMPLES, 3)
    for i in range(25):
        log_time = start_time + datetime.timedelta(seconds=i * 30)
        insert_login_log(
            log_time.strftime("%Y-%m-%d %H:%M:%S"),
            target_ip, random.choice(USERNAMES), random.choice(USER_AGENTS), False,
            attempted_password=breach_passwords[i % len(breach_passwords)]
        )
    insert_login_log(
        (start_time + datetime.timedelta(seconds=25 * 30)).strftime("%Y-%m-%d %H:%M:%S"),
        target_ip, random.choice(USERNAMES), random.choice(USER_AGENTS), True,
        attempted_password=breach_passwords[0]
    )

    # ======================== 攻击样本：规则2 撞库攻击 ========================
    # 规则②判定条件：同一账号在 10 分钟窗口内被 ≥8 个不同 IP 尝试登录
    #
    # 说明：修复"规则②缺少时间窗"的缺陷后，正常客户端不再误触发它（这是正确的），
    # 但若无专门的撞库样本，这条规则在演示中将永远不触发。
    # 这里构造一个典型撞库场景：10 个攻击 IP 各尝试一次，目标是同一个账号。
    # 每个 IP 只失败一次，因此**不会**触发规则①；IP 取自独立池，不污染正常客户端。
    print("正在生成规则2测试数据：10 个 IP 撞库同一账号...")
    cred_stuff_ips = [generate_random_ip() for _ in range(10)]
    stuffed_account = random.choice(USERNAMES)
    # 该组跨度 10x55 秒 ≈ 8.25 分钟，令其末尾落在 now-1 分钟，
    # 则整组位于规则②的 10 分钟窗内
    stuff_start = _at(1 + 10 * 55 / 60.0)
    for i, ip in enumerate(cred_stuff_ips):
        # 10 分钟内均匀铺开，确保落在规则②的 account_time_window(10 分钟) 内
        log_time = stuff_start + datetime.timedelta(seconds=i * 55)
        insert_login_log(
            log_time.strftime("%Y-%m-%d %H:%M:%S"),
            ip, stuffed_account, random.choice(USER_AGENTS), False,
            attempted_password=random.choice(
                ["123456", "password", "admin@2024", "P@ssw0rd", "qwerty123"])
        )

    # ======================== 攻击样本：规则5 慢速暴力破解 ========================
    # 规则⑤判定条件（本次已加短窗口排除项）：
    #   (1) 24 小时内失败 ≥10 次
    #   (2) 平均间隔 ≥30 分钟
    #   (3) 任意 10 分钟窗口内失败数 < 规则①阈值(10) —— 即"成功规避了短窗口检测"
    #
    # 真实特征：攻击者刻意把频率降到每小时一次左右，让任何短窗口看起来都正常。
    # 这里构造 14 次尝试、间隔 40~70 分钟，总跨度约 12 小时，
    # 既满足平均间隔要求，也不会在任何 10 分钟窗口内形成爆发。
    print("正在生成规则5测试数据：1 个 IP 以 40~70 分钟间隔持续试探 12 小时...")
    slow_ip = generate_random_ip()
    slow_start = _at(12 * 60)          # 从 12 小时前开始
    _cursor = slow_start
    for _ in range(14):
        insert_login_log(
            _cursor.strftime("%Y-%m-%d %H:%M:%S"),
            slow_ip, random.choice(USERNAMES), random.choice(USER_AGENTS), False,
            attempted_password=random.choice(["123456", "password", "admin", "P@ssw0rd"])
        )
        _cursor += datetime.timedelta(minutes=random.randint(40, 70))

    # ======================== 攻击样本：规则4 字典攻击 ========================
    # 规则④判定条件：同一 IP 尝试 ≥5 种常见弱密码
    # 这里生成一个"用字典系统性试探"的攻击源：8 种不同弱密码各试一次。
    print("正在生成规则4测试数据：1 个 IP 使用 8 种弱密码进行字典试探...")
    dict_ip = generate_random_ip()
    # 该组跨度 10x45 秒 = 7.5 分钟，与其它组分离
    dict_start = _at(40 + 10 * 45 / 60.0)
    # 抽 10 种（阈值是 5）：留出余量，避免因抽样分布导致规则④时灵时不灵。
    dict_pwds = random.sample(WEAK_PASSWORD_SAMPLES, 10)
    for i, pwd in enumerate(dict_pwds):
        log_time = dict_start + datetime.timedelta(seconds=i * 45)
        insert_login_log(
            log_time.strftime("%Y-%m-%d %H:%M:%S"),
            dict_ip, random.choice(USERNAMES), random.choice(USER_AGENTS), False,
            attempted_password=pwd
        )

    print("模拟日志生成完成！")
