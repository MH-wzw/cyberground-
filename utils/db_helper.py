"""
==============================================================================
  CyberGuard — 数据库操作工具模块
==============================================================================
  封装所有 SQLite 数据库的 CRUD 操作，提供统一的数据库访问层。

  设计思路：
  - 所有函数统一使用 try/except/finally 确保连接正确释放
  - 通过 _get_conn() 统一获取连接，设置超时避免死锁
  - 插入类函数打印操作状态，便于调试和日志追踪
  - alert_exists() 支持按 IP 或用户名去重，防止重复告警

  数据表结构：
  ┌─ login_logs ──────────────────────────────────────┐
  │ 登录日志表 — 记录每次登录尝试的详细信息              │
  │ 字段：id, timestamp, ip_address, username,          │
  │       user_agent, success, created_at               │
  ├─ alerts ───────────────────────────────────────────┤
  │ 告警记录表 — 检测规则触发的安全告警                 │
  │ 字段：id, alert_time, alert_type, risk_level,       │
  │       ip_address, username, attempt_count,           │
  │       description, status, handler_note, created_at  │
  ├─ ip_blacklist ─────────────────────────────────────┤
  │ IP 黑名单表 — 被封禁的 IP 地址及封禁信息             │
  │ 字段：id, ip_address(UNIQUE), reason, block_time,    │
  │       expire_time, created_at                        │
  └────────────────────────────────────────────────────┘
==============================================================================
"""

import sqlite3
import datetime
import sys

# 注意：这里必须 `import config` 而不是 `from config import DATABASE_PATH`。
#
# 原因（此前导致测试写进生产库的真实缺陷）：
#   `from config import DATABASE_PATH` 是在**模块导入时按值绑定**。
#   测试的做法是先把 config.DATABASE_PATH 指向临时文件，再导入 db_helper ——
#   只要 db_helper 在这之前被任何模块（如 utils.notifier）提前导入过一次，
#   它拿到的就已经是生产库路径，之后测试再改 config 也不会生效，
#   于是单元测试实际读写的正是 db.sqlite3。
#   改为每次取配置时动态读取 config.DATABASE_PATH，补丁才真正生效。
import config

import logging
logger = logging.getLogger(__name__)

# Windows 控制台默认 GBK，无法编码 emoji，会让本模块的 print() 抛
# UnicodeEncodeError 并中断初始化流程（例如直接执行脚本或跑测试时）。
# 这里把标准输出切到 UTF-8，使模块在被独立调用时同样健壮。
# 注意：except 是**刻意静默**的 —— 没有 reconfigure 时保持原编码即为正确行为，
# 且 logging 也写同一个流，在此处记日志只会引发二次失败。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# 数据库连接超时设置（秒）
# 设置合理的超时值避免在高并发场景下出现 "database is locked" 错误
DB_TIMEOUT = 10


def _get_conn():
    """
    获取数据库连接（内部辅助函数）

    统一设置连接参数：
    - timeout: 等待锁的超时时间
    - row_factory: 设置为 sqlite3.Row 以便按列名访问

    路径**每次现取** config.DATABASE_PATH（而不是模块级缓存），
    这样测试替换配置后能真正指向临时库，详见文件头部的说明。
    """
    conn = sqlite3.connect(config.DATABASE_PATH, timeout=DB_TIMEOUT)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    初始化数据库 — 创建所有表结构（幂等操作，可重复执行）

    使用 CREATE TABLE IF NOT EXISTS 确保多次调用安全
    表结构设计遵循第三范式（3NF），字段类型选择兼顾性能和扩展性

    Raises:
        sqlite3.Error: 数据库初始化失败时抛出（由上层捕获处理）
    """
    conn = None          # 连接创建失败时 finally 才有对象可判断
    try:
        conn = _get_conn()
        cursor = conn.cursor()

        # 登录日志表 — 核心数据表
        #
        # 关于 attempted_password 列（重要修复）：
        # 原表结构里**没有密码字段**，而检测规则④「字典攻击」却拿 username 字段
        # 去和弱密码表比对 —— 于是它实际拦截的是"用户名恰好叫 admin/root 的正常用户"，
        # 既不能反映真实的字典攻击，又是一个纯粹的误报源。
        # 现在补上"本次登录尝试所使用的口令"，规则④改为比对该列，
        # 使其真正对应"攻击者尝试了多个常见弱密码"这一行为。
        #
        # 安全说明：该列仅存在于演示数据库中，内容为程序生成的弱口令样本
        #（如 "123456"、"password"），用于复现字典攻击场景；
        # 本系统不采集、不存储任何真实用户凭证。
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                ip_address TEXT NOT NULL,
                username TEXT NOT NULL,
                user_agent TEXT,
                success BOOLEAN NOT NULL,
                attempted_password TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # 旧库迁移：已存在的 login_logs 表若缺少 attempted_password 列则补上。
        # SQLite 的 ALTER TABLE ADD COLUMN 是向后兼容的，已有行该列为 NULL。
        cursor.execute("PRAGMA table_info(login_logs)")
        _cols = {row[1] for row in cursor.fetchall()}
        if 'attempted_password' not in _cols:
            cursor.execute('ALTER TABLE login_logs ADD COLUMN attempted_password TEXT')
            print("ℹ️  已为 login_logs 补充 attempted_password 列（旧库自动迁移）")

        # 告警记录表 — 检测引擎输出
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_time DATETIME NOT NULL,
                alert_type TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                ip_address TEXT,
                username TEXT,
                attempt_count INTEGER,
                description TEXT,
                status TEXT DEFAULT '未处理',
                handler_note TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # IP 黑名单表 — 手动/自动封禁记录
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                reason TEXT NOT NULL,
                block_time DATETIME NOT NULL,
                expire_time DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.commit()
        print("✅ 数据库初始化成功！")

    except sqlite3.Error as e:
        logger.error(f"❌ 数据库初始化失败: {e}")
        raise  # 重新抛出异常，让应用层决定如何处理

    finally:
        if conn is not None:
            conn.close()


# ============================================================================
#                         登录日志 CRUD 操作
# ============================================================================

def insert_login_log(timestamp, ip_address, username, user_agent, success,
                     attempted_password=None):
    """
    插入一条登录日志记录

    Args:
        timestamp:          登录时间（格式：YYYY-MM-DD HH:MM:SS）
        ip_address:         客户端 IP 地址
        username:           登录用户名
        user_agent:         浏览器 User-Agent 字符串
        success:            登录是否成功（True/False）
        attempted_password: 本次尝试使用的口令。用于字典攻击检测（规则④）。
                            正常用户登录可传 None —— 真实系统同样没有理由
                            记录合法用户的口令，这也符合最小采集原则。
    """
    conn = None          # 连接创建失败时 finally 才有对象可判断
    try:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO login_logs '
            '(timestamp, ip_address, username, user_agent, success, attempted_password) '
            'VALUES (?, ?, ?, ?, ?, ?)',
            (timestamp, ip_address, username, user_agent, success, attempted_password)
        )
        conn.commit()
    except sqlite3.Error as e:
        logger.error(f"❌ 插入登录日志失败: {e}")
    finally:
        if conn is not None:
            conn.close()


def query_login_logs(ip=None, username=None, success=None,
                     page=1, page_size=50, with_total=True):
    """按条件分页查询登录日志（筛选与分页均在 SQL 层完成）。

    为什么需要这个函数：
      原实现把全量日志取进内存再用 Python 循环过滤、前端切片分页。
      实测全量约 1700 条 / 260KB，且随演示生成的日志持续增长 ——
      每次翻页都要重传整张表，筛选也只是"看起来在筛"。

    安全说明：
      所有条件均使用**参数化占位符**（?），不做字符串拼接，
      因此不存在 SQL 注入面。模糊匹配用 LIKE 并对用户输入中的
      % 与 _ 做转义，避免用户输入 % 时意外匹配全部记录。

    Args:
        ip:        按 IP 模糊匹配（None/空串表示不限）
        username:  按用户名模糊匹配
        success:   按登录结果筛选（True / False / None）
        page:      页码，从 1 开始
        page_size: 每页条数（上限 500，防止被要求一次取回全表）
        with_total: 是否附带总条数（用于分页组件）。首页以外的翻页
                    其实不需要重复统计，但代价很小，保持接口简单。

    Returns:
        dict: {
            'items':     list[tuple]  —— 字段顺序同 get_all_login_logs
            'total':     int          —— 符合条件的总条数
            'page':      int
            'page_size': int
            'pages':     int          —— 总页数
        }
    """
    try:
        page = max(1, int(page or 1))
    except (TypeError, ValueError):
        page = 1
    try:
        page_size = int(page_size or 50)
    except (TypeError, ValueError):
        page_size = 50
    page_size = max(1, min(page_size, 500))

    where, params = [], []

    def _like(value):
        """转义 LIKE 通配符，避免用户输入 % 或 _ 时匹配到全部记录。"""
        v = str(value).replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        return '%' + v + '%'

    if ip:
        where.append("ip_address LIKE ? ESCAPE '\\'")
        params.append(_like(ip))
    if username:
        where.append("username LIKE ? ESCAPE '\\'")
        params.append(_like(username))
    if success is not None and success != '':
        # 兼容 True/False 与 'true'/'false'/'1'/'0'
        s = success
        if isinstance(s, str):
            s = s.strip().lower() in ('1', 'true', 'yes', 'success')
        where.append('success = ?')
        params.append(1 if s else 0)

    clause = (' WHERE ' + ' AND '.join(where)) if where else ''

    conn = None          # 连接创建失败时 finally 才有对象可判断
    try:
        conn = _get_conn()
        cursor = conn.cursor()

        total = 0
        if with_total:
            cursor.execute('SELECT COUNT(*) FROM login_logs' + clause, params)
            total = cursor.fetchone()[0]

        # LIMIT/OFFSET 分页。ORDER BY 加 id 作为次级排序键，
        # 避免同一秒内的多条日志在翻页时顺序不稳定导致记录重复或漏出。
        cursor.execute(
            'SELECT * FROM login_logs' + clause +
            ' ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?',
            params + [page_size, (page - 1) * page_size])
        items = [tuple(r) for r in cursor.fetchall()]

        if not with_total:
            total = len(items)

        return {
            'items': items,
            'total': total,
            'page': page,
            'page_size': page_size,
            'pages': max(1, (total + page_size - 1) // page_size) if total else 0,
        }
    except sqlite3.Error as e:
        logger.error(f"❌ 分页查询登录日志失败: {e}")
        return {'items': [], 'total': 0, 'page': page,
                'page_size': page_size, 'pages': 0}
    finally:
        if conn is not None:
            conn.close()


def count_login_logs(ip=None, username=None, success=None):
    """只取符合条件的日志条数（供统计类调用，避免把数据取回内存）。"""
    return query_login_logs(ip, username, success, page=1, page_size=1)['total']


def get_all_login_logs():
    """
    获取全部登录日志（按时间倒序排列）

    Returns:
        list[tuple]: 登录日志元组列表，空数据库时返回空列表
        每个元组字段顺序：
            id, timestamp, ip_address, username, user_agent, success,
            attempted_password, created_at
        即：log[0]=id, log[1]=时间, log[2]=IP, log[3]=用户名,
            log[4]=User-Agent, log[5]=成功与否, log[6]=尝试的口令
    """
    conn = None          # 连接创建失败时 finally 才有对象可判断
    try:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM login_logs ORDER BY timestamp DESC')
        logs = [tuple(row) for row in cursor.fetchall()]
        return logs
    except sqlite3.Error as e:
        logger.error(f"❌ 查询登录日志失败: {e}")
        return []
    finally:
        if conn is not None:
            conn.close()


# ============================================================================
#                         告警记录 CRUD 操作
# ============================================================================

def insert_alert(alert_time, alert_type, risk_level, ip_address, username, attempt_count, description):
    """
    插入一条告警记录

    Args:
        alert_time:    告警触发时间
        alert_type:    告警类型（如 "IP高频失败攻击"）
        risk_level:    风险等级（高危/中危/低危）
        ip_address:    攻击来源 IP
        username:      目标用户名（可为 None）
        attempt_count: 攻击尝试次数
        description:   告警描述文本

    Returns:
        int | None: 新插入记录的 id，失败时返回 None。
        返回 id 是为了让上层（app.py 的通知钩子）能在写入成功后
        取回该行内容并触发告警通知。
    """
    conn = None          # 连接创建失败时 finally 才有对象可判断
    try:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO alerts (alert_time, alert_type, risk_level, ip_address, '
            'username, attempt_count, description) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (alert_time, alert_type, risk_level, ip_address, username, attempt_count, description)
        )
        conn.commit()
        return cursor.lastrowid
    except sqlite3.Error as e:
        logger.error(f"❌ 插入告警失败: {e}")
        return None
    finally:
        if conn is not None:
            conn.close()


def alert_exists(alert_type, ip_address=None, username=None, within_hours=6):
    """
    检查指定时间窗口内是否已存在同类告警（去重机制）

    设计目的：防止检测引擎在连续运行时产生重复告警。
    支持两种去重维度：
    1. 按用户名去重（用于账号类攻击规则，如"账号多IP攻击"）
    2. 按 IP 地址去重（用于 IP 类攻击规则，如"IP高频失败攻击"）

    Args:
        alert_type:   告警类型
        ip_address:   攻击 IP（可选，按 IP 去重）
        username:     用户名（可选，按用户名去重，优先级高于 IP）
        within_hours: 去重时间窗口（默认 6 小时）

    Returns:
        bool: True 表示已存在同类告警，应跳过插入
    """
    conn = None          # 连接创建失败时 finally 才有对象可判断
    try:
        conn = _get_conn()
        cursor = conn.cursor()
        since = (datetime.datetime.now() - datetime.timedelta(hours=within_hours)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # 按用户名去重（用于"账号多IP攻击"等场景）
        if username:
            cursor.execute(
                'SELECT COUNT(*) FROM alerts '
                'WHERE alert_type = ? AND username = ? AND alert_time >= ?',
                (alert_type, username, since)
            )
        # 按 IP 去重（用于"IP高频失败攻击"等场景）
        elif ip_address:
            cursor.execute(
                'SELECT COUNT(*) FROM alerts '
                'WHERE alert_type = ? AND ip_address = ? AND alert_time >= ?',
                (alert_type, ip_address, since)
            )
        # 无去重维度 — 仅按类型检查
        else:
            cursor.execute(
                'SELECT COUNT(*) FROM alerts '
                'WHERE alert_type = ? AND alert_time >= ?',
                (alert_type, since)
            )

        count = cursor.fetchone()[0]
        return count > 0

    except sqlite3.Error as e:
        logger.error(f"❌ 检查告警是否存在失败: {e}")
        return False  # 出错时保守返回 False，不阻塞告警插入
    finally:
        if conn is not None:
            conn.close()


def get_all_alerts():
    """
    获取全部告警记录（按告警时间倒序排列）

    Returns:
        list[tuple]: 告警元组列表
        字段顺序：id, alert_time, alert_type, risk_level, ip_address,
                 username, attempt_count, description, status, handler_note, created_at
    """
    conn = None          # 连接创建失败时 finally 才有对象可判断
    try:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM alerts ORDER BY alert_time DESC')
        alerts = [tuple(row) for row in cursor.fetchall()]
        return alerts
    except sqlite3.Error as e:
        logger.error(f"❌ 查询告警失败: {e}")
        return []
    finally:
        if conn is not None:
            conn.close()


def update_alert_status(alert_id, status, note):
    """
    更新告警的处理状态和备注

    Args:
        alert_id: 告警记录 ID
        status:   新状态（已处理/误报/忽略）
        note:     处理备注文本
    """
    conn = None          # 连接创建失败时 finally 才有对象可判断
    try:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE alerts SET status = ?, handler_note = ? WHERE id = ?',
            (status, note, alert_id)
        )
        conn.commit()
    except sqlite3.Error as e:
        logger.error(f"❌ 更新告警状态失败: {e}")
    finally:
        if conn is not None:
            conn.close()


# ============================================================================
#                         IP 黑名单 CRUD 操作
# ============================================================================

def add_to_blacklist(ip, reason, block_hours=24):
    """
    将 IP 加入黑名单

    特点：
    - 使用 UNIQUE 约束，重复 IP 会触发 IntegrityError
    - 自动计算过期时间 = 当前时间 + block_hours

    Args:
        ip:         IP 地址
        reason:     封禁原因描述
        block_hours: 封禁时长（小时），默认 24

    Returns:
        bool: True 表示添加成功，False 表示已存在或操作失败
    """
    conn = None          # 连接创建失败时 finally 才有对象可判断
    try:
        conn = _get_conn()
        cursor = conn.cursor()
        block_time = datetime.datetime.now()
        expire_time = block_time + datetime.timedelta(hours=block_hours)
        cursor.execute(
            'INSERT INTO ip_blacklist (ip_address, reason, block_time, expire_time) '
            'VALUES (?, ?, ?, ?)',
            (ip, reason,
             block_time.strftime("%Y-%m-%d %H:%M:%S"),
             expire_time.strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        print(f"✅ IP {ip} 已加入黑名单，封禁{block_hours}小时")
        return True

    except sqlite3.IntegrityError:
        # UNIQUE 约束冲突 → IP 已在黑名单中
        print(f"⚠️ IP {ip} 已在黑名单中")
        return False

    except sqlite3.Error as e:
        logger.error(f"❌ 添加黑名单失败: {e}")
        return False

    finally:
        if conn is not None:
            conn.close()


def remove_from_blacklist(ip):
    """
    从黑名单中移除指定 IP

    Args:
        ip: 要移除的 IP 地址

    Returns:
        bool: True 表示成功删除，False 表示未找到或操作失败
    """
    conn = None          # 连接创建失败时 finally 才有对象可判断
    try:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM ip_blacklist WHERE ip_address = ?', (ip,))
        conn.commit()
        affected = cursor.rowcount
        return affected > 0
    except sqlite3.Error as e:
        logger.error(f"❌ 移除黑名单失败: {e}")
        return False
    finally:
        if conn is not None:
            conn.close()


def get_all_blacklist():
    """
    获取全部黑名单记录（按封禁时间倒序）

    Returns:
        list[tuple]: 黑名单元组列表
        字段顺序：id, ip_address, reason, block_time, expire_time, created_at
    """
    conn = None          # 连接创建失败时 finally 才有对象可判断
    try:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM ip_blacklist ORDER BY block_time DESC')
        blacklist = [tuple(row) for row in cursor.fetchall()]
        return blacklist
    except sqlite3.Error as e:
        logger.error(f"❌ 查询黑名单失败: {e}")
        return []
    finally:
        if conn is not None:
            conn.close()


def get_alert_summary(hours=None):
    """告警的**服务端聚合**统计。

    为什么需要它：
      态势大屏只需要 4 个计数（未处理 / 已处理 / 误报 / 高危）和规则命中的 TOP3，
      但原先的做法是把 /api/alerts 的**全量记录**（实测 3000+ 条、约 1MB）
      拉到浏览器里再 filter —— 每 30 秒一次，等于持续传输与解析无用数据。
      这里改为在 SQL 层 GROUP BY 完成，返回一个几百字节的对象。

    Args:
        hours: 只看最近多少小时；None 表示全部。用于配合大屏的时间窗口筛选。

    Returns:
        dict: {total, pending, handled, false_positive, high, medium, low, top_rules}
    """
    conn = None          # 连接创建失败时 finally 才有对象可判断
    try:
        conn = _get_conn()
        cursor = conn.cursor()

        where, params = '', ()
        if hours:
            since = (datetime.datetime.now()
                     - datetime.timedelta(hours=float(hours))
                     ).strftime('%Y-%m-%d %H:%M:%S')
            where = ' WHERE alert_time >= ?'
            params = (since,)

        # 按状态聚合
        cursor.execute(
            'SELECT status, COUNT(*) FROM alerts' + where + ' GROUP BY status', params)
        status_map = {(row[0] or '未处理'): row[1] for row in cursor.fetchall()}

        # 按风险等级聚合
        cursor.execute(
            'SELECT risk_level, COUNT(*) FROM alerts' + where
            + ' GROUP BY risk_level', params)
        risk_map = {row[0]: row[1] for row in cursor.fetchall()}

        # 规则命中 TOP3
        cursor.execute(
            'SELECT alert_type, COUNT(*) AS c FROM alerts' + where
            + ' GROUP BY alert_type ORDER BY c DESC LIMIT 3', params)
        top_rules = [{'name': row[0] or '未知规则', 'count': row[1]}
                     for row in cursor.fetchall()]

        total = sum(status_map.values())
        return {
            'total': total,
            'pending': status_map.get('未处理', 0),
            'handled': status_map.get('已处理', 0),
            'false_positive': status_map.get('误报', 0),
            'high': risk_map.get('高危', 0),
            'medium': risk_map.get('中危', 0),
            'low': risk_map.get('低危', 0),
            'top_rules': top_rules,
        }
    except sqlite3.Error as e:
        logger.error(f"❌ 统计告警失败: {e}")
        return {'total': 0, 'pending': 0, 'handled': 0, 'false_positive': 0,
                'high': 0, 'medium': 0, 'low': 0, 'top_rules': []}
    finally:
        if conn is not None:
            conn.close()
