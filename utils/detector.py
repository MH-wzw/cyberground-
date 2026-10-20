"""
==============================================================================
  CyberGuard — 暴力破解检测引擎
==============================================================================
  本模块实现了 5 条暴力破解检测规则，每条规则针对一种特定的攻击模式。

  检测规则概览：
  ┌──────────────────────────────────────────────────────────────────┐
  │ 规则1：IP 高频失败攻击                                           │
  │   在指定时间窗口内，同一 IP 的失败登录次数达到阈值 → 触发告警     │
  │   典型场景：攻击者用同一台机器高速尝试不同密码                    │
  ├──────────────────────────────────────────────────────────────────┤
  │ 规则2：账号多 IP 攻击（撞库攻击）                                 │
  │   同一账号被来自多个不同 IP 的请求尝试登录 → 触发告警             │
  │   典型场景：攻击者用分布式代理尝试撞库                            │
  ├──────────────────────────────────────────────────────────────────┤
  │ 规则3：高频失败 + 零星成功攻击                                    │
  │   在时间窗口内失败次数极高（≥20）且成功次数极少（≤2）              │
  │   典型场景：暴力破解成功 — 攻击者最终猜中了密码                   │
  ├──────────────────────────────────────────────────────────────────┤
  │ 规则4：字典攻击                                                   │
  │   同一 IP 尝试了 5 个以上常见弱密码 → 触发告警                    │
  │   典型场景：攻击者使用弱密码字典进行批量尝试                      │
  ├──────────────────────────────────────────────────────────────────┤
  │ 规则5：慢速暴力破解                                               │
  │   在 24 小时内，平均间隔 ≥30 分钟，持续尝试 ≥10 次                │
  │   典型场景：攻击者降低频率以规避检测阈值                          │
  └──────────────────────────────────────────────────────────────────┘

  算法核心思想：
  - 基于时间窗口的滑动计数（规则1、3）
  - 基于集合的去重计数（规则2、4）
  - 基于时间间隔均值的统计分析（规则5）

  设计决策：
  - 每条规则独立执行，互不依赖，方便单独测试和调整
  - 使用 alert_exists() 去重，避免重复告警
  - 检测到攻击后自动加入黑名单，封禁时长按严重程度分级
==============================================================================
"""

import datetime
from collections import defaultdict
from utils.db_helper import get_all_login_logs, insert_alert, add_to_blacklist, alert_exists
import config

import logging
logger = logging.getLogger(__name__)


def detect_ip_frequency_attack():
    """
    规则1：IP 高频失败攻击检测

    算法流程：
    1. 从数据库获取全部日志，筛选失败记录
    2. 按 IP 分组，每个 IP 维护一个失败时间列表
    3. 对每个 IP 的时间列表排序后滑动窗口检查：
       如果窗口内的失败次数 ≥ threshold 且时间跨度 ≤ window_seconds → 触发告警

    时间复杂度：O(n + k*m)，n=总日志数，k=IP数，m=每IP平均失败次数
    """
    try:
        logs = get_all_login_logs()

        # 步骤1：按 IP 分组收集失败登录时间
        ip_failure_counts = defaultdict(list)
        for log in logs:
            if not log[5]:  # log[5] = success（False 表示失败）
                log_time = datetime.datetime.strptime(log[1], "%Y-%m-%d %H:%M:%S")
                ip_failure_counts[log[2]].append(log_time)

        # 步骤2：读取配置阈值
        threshold = config.DETECTION_RULES["ip_failure_threshold"]
        window_seconds = config.DETECTION_RULES["ip_time_window"] * 60  # 分钟转秒

        # 步骤3：滑动窗口检测
        for ip, times in ip_failure_counts.items():
            if len(times) >= threshold:
                times.sort()
                # 滑动窗口：检查任意连续 threshold 个时间点是否在窗口内
                for i in range(len(times) - threshold + 1):
                    # 窗口 = [i, i+threshold-1]，检查两端时间差
                    if (times[i + threshold - 1] - times[i]).total_seconds() <= window_seconds:
                        # 去重检查：6 小时内是否已有同类告警
                        if not alert_exists("IP高频失败攻击", ip):
                            insert_alert(
                                alert_time=times[i + threshold - 1].strftime(
                                    "%Y-%m-%d %H:%M:%S"
                                ),
                                alert_type="IP高频失败攻击",
                                risk_level="中危",
                                ip_address=ip,
                                username=None,
                                attempt_count=threshold,
                                description=(
                                    f"IP {ip} 在{config.DETECTION_RULES['ip_time_window']}"
                                    f"分钟内失败{threshold}次"
                                )
                            )
                            # 自动封禁 12 小时
                            add_to_blacklist(ip, "IP高频失败攻击", block_hours=12)
                        break  # 每个 IP 只告警一次
        print("✅ 规则1检测完成")
    except Exception as e:
        logger.error(f"❌ 规则1检测失败: {str(e)}")
def detect_account_multi_ip_attack():
    """
    规则2：账号多 IP 攻击检测（撞库攻击）

    算法流程：
    1. 筛选失败登录记录，按用户名分组，收集每个用户名被尝试的 IP 集合
    2. 如果某用户名的 IP 数量 ≥ threshold → 触发告警
    3. 所有涉及的 IP 全部加入黑名单

    告警去重维度：按用户名（而非 IP），因为同账号可能被不同 IP 反复攻击
    """
    try:
        logs = get_all_login_logs()

        # 步骤1：按用户名分组，收集失败登录的 IP 集合
        # ---------------------------------------------------------------
        # BUG 修复（重要）：原实现统计的是**全部历史日志**里尝试过该账号的
        # 不同 IP 总数，完全没有使用配置项 account_time_window（10 分钟）。
        # 这会让"长期运行的系统里，一个通用账号在数月内被多个 IP 登录过"
        # 直接满足 ≥8 的阈值，从而把大批正常 IP 判定为撞库并连锁封禁
        # （实测：872 条封禁中 843 条，即 96.7%，由此产生，属典型高误报）。
        # 现在改为只在配置的时间窗口内统计不同 IP 数。
        # ---------------------------------------------------------------
        window_minutes = config.DETECTION_RULES.get("account_time_window", 10)
        since = datetime.datetime.now() - datetime.timedelta(minutes=window_minutes)

        account_ips = defaultdict(set)
        for log in logs:
            if log[5]:                      # 只统计失败登录
                continue
            try:
                log_time = datetime.datetime.strptime(log[1], "%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                continue
            if log_time < since:            # 窗口外的事件不参与判定
                continue
            account_ips[log[3]].add(log[2])  # log[3]=username, log[2]=ip

        threshold = config.DETECTION_RULES["account_ip_threshold"]

        # 步骤2：检查每个用户名在时间窗口内的 IP 多样性
        for username, ips in account_ips.items():
            if len(ips) >= threshold:
                # 获取该用户最后一次失败登录的时间作为告警时间
                account_logs = [
                    log for log in logs
                    if log[3] == username and not log[5]
                ]
                if account_logs:
                    latest_time = max(
                        datetime.datetime.strptime(log[1], "%Y-%m-%d %H:%M:%S")
                        for log in account_logs
                    )
                else:
                    latest_time = datetime.datetime.now()

                # 按用户名去重（不同 IP 攻击同一账号只告警一次）
                if not alert_exists("账号多IP攻击", username=username):
                    insert_alert(
                        alert_time=latest_time.strftime("%Y-%m-%d %H:%M:%S"),
                        alert_type="账号多IP攻击",
                        risk_level="高危",  # 撞库攻击风险最高
                        ip_address=",".join(ips),  # 多个 IP 用逗号连接
                        username=username,
                        attempt_count=len(ips),
                        description=f"账号 {username} 被{len(ips)}个不同IP尝试登录"
                    )

                # 将所有涉及 IP 加入黑名单，封禁 168 小时（7天）
                for ip in ips:
                    add_to_blacklist(ip, "账号多IP攻击", block_hours=168)

        print("✅ 规则2检测完成")
    except Exception as e:
        logger.error(f"❌ 规则2检测失败: {str(e)}")
def detect_high_frequency_attack():
    """
    规则3：高频失败 + 零星成功攻击检测（暴力破解成功）

    算法流程：
    1. 按 IP 分组，记录每次尝试的时间和结果
    2. 对每个 IP，使用双指针滑动窗口：
       右指针扩展窗口 → 左指针收缩以维持窗口大小 ≤ window_seconds
    3. 在窗口中分别统计失败次数和成功次数
    4. 如果失败次数 ≥ failure_threshold 且成功次数 ≤ success_threshold → 触发告警

    双指针滑动窗口的优势：
    - 避免 O(n²) 的暴力枚举
    - 时间复杂度 O(n*k)，n=每IP尝试次数，k=窗口内平均数据量

    该规则封禁时长最长（720小时=30天），因为这意味着攻击可能已经成功
    """
    try:
        logs = get_all_login_logs()

        # 步骤1：按 IP 分组，记录（时间, 是否成功）
        ip_attempts = defaultdict(list)
        for log in logs:
            log_time = datetime.datetime.strptime(log[1], "%Y-%m-%d %H:%M:%S")
            ip_attempts[log[2]].append((log_time, log[5]))  # log[5]=success

        # 步骤2：读取配置
        failure_threshold = config.DETECTION_RULES["high_failure_threshold"]
        success_threshold = config.DETECTION_RULES["success_threshold"]
        window_seconds = config.DETECTION_RULES["high_time_window"] * 60

        # 步骤3：双指针滑动窗口检测
        for ip, attempts in ip_attempts.items():
            if len(attempts) >= failure_threshold:
                attempts.sort(key=lambda x: x[0])  # 按时间排序

                left = 0  # 窗口左边界
                for right in range(len(attempts)):
                    # 收缩左边界，确保窗口 ≤ window_seconds
                    while (attempts[right][0] - attempts[left][0]).total_seconds() > window_seconds:
                        left += 1

                    # 统计窗口内的成功/失败次数
                    window_attempts = attempts[left:right + 1]
                    failure_count = sum(1 for _, success in window_attempts if not success)
                    success_count = sum(1 for _, success in window_attempts if success)

                    # 判定条件：高失败 + 低成功
                    if failure_count >= failure_threshold and success_count <= success_threshold:
                        if not alert_exists("高频失败+零星成功攻击", ip):
                            insert_alert(
                                alert_time=attempts[right][0].strftime("%Y-%m-%d %H:%M:%S"),
                                alert_type="高频失败+零星成功攻击",
                                risk_level="高危",
                                ip_address=ip,
                                username=None,
                                attempt_count=failure_count + success_count,
                                description=(
                                    f"IP {ip} 在{config.DETECTION_RULES['high_time_window']}"
                                    f"分钟内失败{failure_count}次，成功{success_count}次，"
                                    f"疑似暴力破解成功"
                                )
                            )
                            # 最严格封禁：30 天
                            add_to_blacklist(ip, "疑似暴力破解成功", block_hours=720)
                        break  # 每个 IP 只告警一次
        print("✅ 规则3检测完成")
    except Exception as e:
        logger.error(f"❌ 规则3检测失败: {str(e)}")
def detect_dictionary_attack():
    """
    规则4：字典攻击检测

    算法流程：
    1. 从配置中读取弱密码库（COMMON_WEAK_PASSWORDS）
    2. 筛选失败登录 + 密码在弱密码库中的记录
    3. 按 IP 分组，收集每个 IP 尝试的弱密码集合
    4. 弱密码种类 ≥ 5 → 触发告警

    设计理念：攻击者使用弱密码字典试探大量密码时，每个密码本身就是"弱密码"，
    而不是看尝试的总次数。这种方式可以检测到"低频但多样"的字典攻击。
    """
    try:
        logs = get_all_login_logs()

        # 步骤1&2：筛选失败 + 口令命中弱密码表的登录记录
        #
        # BUG 修复说明（重要）：
        # 原实现用 log[3]（**username 字段**）去和弱密码表比对，而原表结构中
        # 根本没有密码列 —— 于是它实际拦下的是"用户名恰好叫 admin/root 的正常用户"，
        # 既不能反映真实字典攻击，又是一个纯粹的误报源。
        # 现在表结构已补充 attempted_password 列，这里改用该列做真实比对。
        ip_weak_password_attempts = defaultdict(set)
        for log in logs:
            if log[5]:
                continue                       # 只看失败尝试
            pwd = log[6] if len(log) > 6 else None
            if pwd and pwd in config.COMMON_WEAK_PASSWORDS:
                ip_weak_password_attempts[log[2]].add(pwd)

        # 步骤3：检查每个 IP 的弱密码尝试种类
        for ip, passwords in ip_weak_password_attempts.items():
            if len(passwords) >= 5:  # 尝试了 5 种以上弱密码
                if not alert_exists("字典攻击", ip):
                    # 获取该 IP 最后一次尝试弱密码的时间
                    ip_logs = [
                        log for log in logs
                        if log[2] == ip and not log[5]
                        and (len(log) > 6 and log[6] in config.COMMON_WEAK_PASSWORDS)
                    ]
                    if ip_logs:
                        latest_time = max(
                            datetime.datetime.strptime(log[1], "%Y-%m-%d %H:%M:%S")
                            for log in ip_logs
                        )
                    else:
                        latest_time = datetime.datetime.now()

                    insert_alert(
                        alert_time=latest_time.strftime("%Y-%m-%d %H:%M:%S"),
                        alert_type="字典攻击",
                        risk_level="高危",
                        ip_address=ip,
                        username=None,
                        attempt_count=len(passwords),
                        description=f"IP {ip} 尝试了{len(passwords)}个常见弱密码"
                    )
                    # 封禁 7 天
                    add_to_blacklist(ip, "字典攻击", block_hours=168)
        print("✅ 规则4检测完成")
    except Exception as e:
        logger.error(f"❌ 规则4检测失败: {str(e)}")
def detect_slow_brute_force():
    """
    规则5：慢速暴力破解检测

    算法流程：
    1. 筛选失败登录记录，按 IP 分组收集时间点
    2. 对每个 IP，如果失败次数 ≥ min_attempts（默认 10）：
       a. 计算相邻失败之间的平均时间间隔
       b. 检查是否满足：总时间跨度 ≤ 24 小时 + 平均间隔 ≥ min_interval_seconds
    3. 满足条件 → 触发告警

    设计难点：
    慢速暴力破解是检测盲区的重点，因为攻击者刻意降低频率以规避规则1的检测。
    通过"长周期平均间隔分析"来捕获这类攻击——攻击者可以在 24 小时内
    平均每 30-60 分钟尝试一次，单看短窗口完全正常，但拉长到 24 小时就很可疑。
    """
    try:
        logs = get_all_login_logs()

        # 步骤1：按 IP 分组收集失败登录时间
        ip_failures = defaultdict(list)
        for log in logs:
            if not log[5]:
                log_time = datetime.datetime.strptime(log[1], "%Y-%m-%d %H:%M:%S")
                ip_failures[log[2]].append(log_time)

        # 步骤2：读取配置（带默认值兜底）
        min_attempts = config.DETECTION_RULES.get("slow_brute_force_threshold", 10)
        min_interval_seconds = config.DETECTION_RULES.get(
            "slow_brute_force_interval_minutes", 30
        ) * 60  # 分钟转秒

        # 步骤3：对每个 IP 进行统计分析
        for ip, times in ip_failures.items():
            if len(times) >= min_attempts:
                times.sort()

                # 至少需要 2 个点才能计算间隔
                if len(times) < 2:
                    continue

                # 计算平均尝试间隔
                total_interval = sum(
                    (times[i] - times[i - 1]).total_seconds()
                    for i in range(1, len(times))
                )
                avg_interval = total_interval / (len(times) - 1)

                # 判定条件：
                # (1) 总时间跨度 ≤ 24 小时（攻击者在一天内持续尝试）
                # (2) 平均间隔 ≥ min_interval_seconds（刻意降低频率）
                # (3) 【新增】10 分钟短窗口内失败次数 < 规则①阈值
                #
                # 为什么要加条件 (3)：
                # 原判定只看"24 小时内平均间隔"，于是任何**稀疏但分散**的失败
                # 都会命中。实测中"用字典系统性试探"的攻击源（8 次尝试间隔 45 秒，
                # 平均间隔正好 45 秒 ≥ 30 秒阈值）被同时判为慢速暴力破解，
                # 造成一条攻击行为触发两条告警 —— 两条规则语义重叠、互相污染。
                # 慢速暴力破解的本质特征是"**规避短窗口检测**"，
                # 因此只在短窗口内失败次数确实未达规则①阈值时才判定。
                short_window = 10 * 60
                burst = 0
                _l = 0
                for _r in range(len(times)):
                    while (times[_r] - times[_l]).total_seconds() > short_window:
                        _l += 1
                    burst = max(burst, _r - _l + 1)

                total_span = (times[-1] - times[0]).total_seconds()
                _fast_threshold = config.DETECTION_RULES.get("ip_failure_threshold", 10)
                if (total_span <= 24 * 3600
                        and avg_interval >= min_interval_seconds
                        and burst < _fast_threshold):
                    if not alert_exists("慢速暴力破解", ip):
                        insert_alert(
                            alert_time=times[-1].strftime("%Y-%m-%d %H:%M:%S"),
                            alert_type="慢速暴力破解",
                            risk_level="高危",
                            ip_address=ip,
                            username=None,
                            attempt_count=len(times),
                            description=(
                                f"IP {ip} 在24小时内平均每{int(avg_interval/60)}分钟"
                                f"尝试一次登录，疑似慢速暴力破解"
                            )
                        )
                        # 封禁 14 天（比常规攻击更严，因为是持续性攻击）
                        add_to_blacklist(ip, "慢速暴力破解", block_hours=336)
        print("✅ 规则5检测完成")
    except Exception as e:
        logger.error(f"❌ 规则5检测失败: {str(e)}")
def run_all_detections():
    """
    依次执行全部 5 条检测规则

    设计说明：
    每条规则独立执行且异常隔离——某一规则失败不影响其他规则继续运行。
    这样即使某条规则因数据异常而崩溃，其他检测仍能正常完成。

    Returns:
        bool: 始终返回 True（所有规则已执行）
    """
    print("🔍 开始执行暴力破解检测...")

    # 按规则编号依次执行
    detect_ip_frequency_attack()       # 规则1：IP高频失败攻击
    detect_account_multi_ip_attack()   # 规则2：账号多IP攻击
    detect_high_frequency_attack()     # 规则3：高频失败+零星成功
    detect_dictionary_attack()         # 规则4：字典攻击
    detect_slow_brute_force()          # 规则5：慢速暴力破解

    print("✅ 所有5条检测规则执行完成！")
    return True
