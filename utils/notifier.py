"""
==============================================================================
  CyberGuard — 告警通知系统
==============================================================================
  作用：补齐安全运营闭环中「告警触达」这一环。
  当没有人盯着大屏时，把达标的高危告警推送到值班人邮箱。

  链路：
      告警落库 ──► 通知规则引擎 ──► 聚合缓冲 ──► 渠道分发器 ──► 投递留痕
                      │                              │
              ①等级阈值 ②静默时段             邮件(SMTP)
              ③去重     ④限流                 本地存底(.eml)

  ─────────────────────────────────────────────────────────────────────
  三条核心设计原则
  ─────────────────────────────────────────────────────────────────────
  1. **通知决策在服务端**。若由前端决定发不发，刷新页面、多开标签页
     就会重复推送；而且前端不可信，权限绕过即可滥发邮件。
  2. **投递异步化 + 超时 + 失败隔离**。SMTP 可能超时或拒信，
     绝不能因为发不出邮件而阻塞告警生成与主业务流程。
  3. **全量留痕**。成功、失败、被去重、被限流、被静默，全部落库，
     可在页面审计。这也是本项目「数据透明」原则的延续。

  ─────────────────────────────────────────────────────────────────────
  为什么必须做去重与限流（而不是"有告警就发"）
  ─────────────────────────────────────────────────────────────────────
  攻击浪潮突袭期的告警速率实测可达 70 条/分钟。如果每条告警都发一封邮件，
  一小时内就能把收件箱彻底淹没 —— 这在安全运营里叫 **告警疲劳
  (alert fatigue)**，其真实后果是值班人直接关掉通知，
  于是真正的高危告警反而被忽略。本系统用三层防护对抗它：
      去重（同源同类型 5 分钟一次） → 限流（5 分钟最多 3 封） → 聚合（N 条合并为 1 封）
==============================================================================
"""

import io
import os
import re
import time
import html
import smtplib
import threading
import datetime
import email.utils
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from collections import deque

from utils.db_helper import _get_conn
from config import (
    NOTIFY_RULES, NOTIFY_MAX_ALERTS_PER_MAIL,
    NOTIFY_SMTP_TIMEOUT, NOTIFY_OUTBOX_DIR,
)

import logging
logger = logging.getLogger(__name__)


# ============================================================================
#                              常量与状态
# ============================================================================

RISK_ORDER = {"低危": 1, "中危": 2, "高危": 3}

CHANNEL_EMAIL = "email"

# 投递状态
ST_SENT = "sent"                  # 已送达
ST_FAILED = "failed"              # 投递失败
ST_DEDUPED = "deduped"            # 被去重
ST_RATE_LIMITED = "rate_limited"  # 被限流
ST_QUIET = "skipped_quiet"        # 静默时段跳过
ST_BELOW = "skipped_below_risk"   # 低于风险阈值
ST_NO_RECIPIENT = "skipped_no_recipient"   # 无启用的收件人
ST_NOT_CONFIGURED = "skipped_not_configured"  # SMTP 未配置

_lock = threading.Lock()

# 去重表：key = "类型|IP" -> 上次通知时间戳
_dedup_seen = {}

# 限流：最近投递时间戳队列（仅记录真正发出的邮件）
_sent_times = deque(maxlen=200)

# 聚合缓冲：待合并的告警
_pending = []
_pending_since = None

# 后台投递线程
_worker = None
_worker_stop = threading.Event()


# ============================================================================
#                              配置读写
# ============================================================================

_ENV_SMTP = {
    "host": "CYBERGUARD_SMTP_HOST",
    "port": "CYBERGUARD_SMTP_PORT",
    "user": "CYBERGUARD_SMTP_USER",
    "password": "CYBERGUARD_SMTP_PASS",
    "sender": "CYBERGUARD_SMTP_FROM",
    "use_tls": "CYBERGUARD_SMTP_TLS",
}

_SMTP_DEFAULTS = {
    "host": "",
    "port": "465",
    "user": "",
    "password": "",
    "sender": "",
    "use_tls": "1",      # 1 = SSL/TLS 直连（465）；0 = STARTTLS（587）
}


def init_notify_db():
    """创建通知相关的三张表（幂等）。"""
    conn = _get_conn()
    try:
        cur = conn.cursor()

        # 通知配置 —— 采用 key-value 结构，便于扩展渠道而不改表
        cur.execute('''
            CREATE TABLE IF NOT EXISTS notify_config (
                key        TEXT PRIMARY KEY,
                value      TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # 收件人列表 —— 支持按人设置最低风险等级（值班组里可以有人只看高危）
        cur.execute('''
            CREATE TABLE IF NOT EXISTS notify_recipients (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                email      TEXT NOT NULL UNIQUE,
                name       TEXT,
                min_risk   TEXT NOT NULL DEFAULT '高危',
                enabled    INTEGER NOT NULL DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # 投递留痕 —— 每一次"本该通知"的告警都会留下记录，含被跳过的
        cur.execute('''
            CREATE TABLE IF NOT EXISTS notify_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                alert_id   INTEGER,
                channel    TEXT,
                alert_type TEXT,
                risk_level TEXT,
                source_ip  TEXT,
                status     TEXT,
                detail     TEXT,
                recipient  TEXT,
                latency_ms INTEGER
            )
        ''')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_notify_log_time '
                    'ON notify_log(created_at DESC)')

        conn.commit()
    finally:
        conn.close()


def _cfg_get(key, default=None):
    """读配置：环境变量优先，其次数据库，最后默认值。

    注意：**空字符串是合法配置**（例如把静默时段设为空表示关闭），
    因此不能简单用 `if v` 判断 —— 那样"显式设为空"会被当成"未设置"
    而回落到默认值，用户就无法关闭静默时段。这里用哨兵区分三态。
    """
    _MISSING = object()
    env_key = _ENV_SMTP.get(key)
    if env_key:
        v = os.environ.get(env_key)
        if v is not None and v.strip() != '':
            return v.strip()
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute('SELECT value FROM notify_config WHERE key = ?', (key,))
        row = cur.fetchone()
        if row is None or row[0] is None:
            return default
        return row[0]          # 含空字符串
    except Exception:
        return default
    finally:
        conn.close()


def _cfg_set(key, value):
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO notify_config (key, value, updated_at) VALUES (?, ?, ?) '
            'ON CONFLICT(key) DO UPDATE SET value = excluded.value, '
            'updated_at = excluded.updated_at',
            (key, str(value), datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        )
        conn.commit()
    finally:
        conn.close()


def smtp_config(mask=True):
    """返回 SMTP 配置。

    Args:
        mask: True 时对密码做掩码 —— 供界面回显使用。
              密码**永不**以明文返回给前端。
    """
    cfg = {}
    for k, default in _SMTP_DEFAULTS.items():
        cfg[k] = _cfg_get(k, default) or ""
    # 标明各项是否来自环境变量（环境变量优先级高于库，界面需提示）
    cfg["_from_env"] = {k: bool(os.environ.get(v)) for k, v in _ENV_SMTP.items()}
    if mask and cfg.get("password"):
        cfg["password"] = "********"
        cfg["_has_password"] = True
    else:
        cfg["_has_password"] = bool(cfg.get("password"))
    if cfg.get("sender"):
        cfg["_sender_masked"] = cfg["sender"]
    return cfg


def save_smtp_config(data):
    """保存 SMTP 配置。传入掩码密码（********）表示不修改原密码。"""
    allowed = set(_SMTP_DEFAULTS.keys())
    for k, v in (data or {}).items():
        if k not in allowed:
            continue
        v = "" if v is None else str(v).strip()
        # 前端回显的是掩码，收到掩码说明用户没改密码，跳过
        if k == "password" and v == "********":
            continue
        _cfg_set(k, v)


def rules_config():
    """返回通知规则（配置项优先，缺省用 config.py 默认值）。"""
    out = {}
    for k, default in NOTIFY_RULES.items():
        # 注意：传入 default=None 以区分"库中不存在"与"库中显式设为空"
        v = _cfg_get("rule." + k, None)
        out[k] = default if v is None else v
    # 数值化
    for k in ("dedup_minutes", "rate_limit_window_minutes", "rate_limit_max",
              "aggregate_seconds"):
        try:
            out[k] = int(out[k])
        except (TypeError, ValueError):
            out[k] = NOTIFY_RULES[k]
    return out


def save_rules_config(data):
    allowed = set(NOTIFY_RULES.keys())
    for k, v in (data or {}).items():
        if k in allowed:
            _cfg_set("rule." + k, "" if v is None else str(v).strip())


# ============================================================================
#                              收件人管理
# ============================================================================

_EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$')


def list_recipients(only_enabled=False):
    conn = _get_conn()
    try:
        cur = conn.cursor()
        sql = ('SELECT id, email, name, min_risk, enabled, created_at '
               'FROM notify_recipients')
        if only_enabled:
            sql += ' WHERE enabled = 1'
        sql += ' ORDER BY id ASC'
        cur.execute(sql)
        cols = ['id', 'email', 'name', 'min_risk', 'enabled', 'created_at']
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        conn.close()


def add_recipient(email_addr, name='', min_risk='高危'):
    email_addr = (email_addr or '').strip().lower()
    if not _EMAIL_RE.match(email_addr):
        return False, '邮箱格式不正确'
    if min_risk not in RISK_ORDER:
        min_risk = '高危'
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute('SELECT id FROM notify_recipients WHERE email = ?', (email_addr,))
        if cur.fetchone():
            return False, '该邮箱已在收件人列表中'
        cur.execute(
            'INSERT INTO notify_recipients (email, name, min_risk, enabled) '
            'VALUES (?, ?, ?, 1)',
            (email_addr, (name or '').strip(), min_risk)
        )
        conn.commit()
        return True, '已添加'
    except Exception as e:
        return False, '添加失败：{}'.format(e)
    finally:
        conn.close()


def update_recipient(rid, name=None, min_risk=None, enabled=None):
    sets, params = [], []
    if name is not None:
        sets.append('name = ?'); params.append(str(name).strip())
    if min_risk in RISK_ORDER:
        sets.append('min_risk = ?'); params.append(min_risk)
    if enabled is not None:
        sets.append('enabled = ?'); params.append(1 if enabled else 0)
    if not sets:
        return False, '没有需要更新的字段'
    conn = _get_conn()
    try:
        cur = conn.cursor()
        params.append(rid)
        cur.execute('UPDATE notify_recipients SET {} WHERE id = ?'.format(
            ', '.join(sets)), params)
        conn.commit()
        return (cur.rowcount > 0), ('已更新' if cur.rowcount > 0 else '收件人不存在')
    finally:
        conn.close()


def delete_recipient(rid):
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute('DELETE FROM notify_recipients WHERE id = ?', (rid,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


# ============================================================================
#                              规则引擎
# ============================================================================

def _risk_ge(risk, threshold):
    """判断 risk 是否 >= threshold。"""
    return RISK_ORDER.get(risk, 0) >= RISK_ORDER.get(threshold, 0)


def _in_quiet_hours(now=None):
    """判断当前是否处于静默时段。支持跨零点区间（如 22:00-08:00）。"""
    rules = rules_config()
    span = (rules.get('quiet_hours') or '').strip()
    if not span or '-' not in span:
        return False
    try:
        start_s, end_s = span.split('-', 1)
        sh, sm = [int(x) for x in start_s.strip().split(':')]
        eh, em = [int(x) for x in end_s.strip().split(':')]
    except (ValueError, AttributeError):
        return False
    now = now or datetime.datetime.now()
    cur = now.hour * 60 + now.minute
    start, end = sh * 60 + sm, eh * 60 + em
    if start <= end:
        return start <= cur < end
    # 跨零点，例如 22:00-08:00
    return cur >= start or cur < end


def _dedup_key(alert):
    return '{}|{}'.format(alert.get('alert_type') or '', alert.get('source_ip') or '')


def _passes_dedup(alert, rules):
    """去重：同源 + 同类型在窗口内只放行一次。返回 (是否放行, 说明)。"""
    minutes = max(1, int(rules.get('dedup_minutes') or 5))
    key = _dedup_key(alert)
    now = time.time()
    with _lock:
        last = _dedup_seen.get(key)
        if last is not None and (now - last) < minutes * 60:
            return False, '同源同类型告警在 {} 分钟内已通知过（剩余 {:.0f} 秒）'.format(
                minutes, minutes * 60 - (now - last))
        _dedup_seen[key] = now
        # 顺带清理过期键，避免字典无限增长
        if len(_dedup_seen) > 5000:
            cutoff = now - minutes * 60
            for k in [k for k, v in _dedup_seen.items() if v < cutoff]:
                _dedup_seen.pop(k, None)
    return True, ''


def _passes_rate_limit(rules):
    """限流：窗口内投递数达到上限则拒绝。返回 (是否放行, 说明)。"""
    window = max(1, int(rules.get('rate_limit_window_minutes') or 5)) * 60
    limit = max(1, int(rules.get('rate_limit_max') or 3))
    now = time.time()
    with _lock:
        recent = [t for t in _sent_times if now - t < window]
        if len(recent) >= limit:
            return False, '{} 分钟内已投递 {} 封，达到限流上限'.format(
                window // 60, limit)
    return True, ''


def _mark_sent():
    with _lock:
        _sent_times.append(time.time())


def evaluate(alert):
    """对单条告警执行规则评估。

    Returns:
        (是否放行, 状态码, 说明)
    评估顺序即优先级：先做廉价判断（开关、阈值、静默），
    再做需要维护状态的判断（去重、限流）。
    """
    rules = rules_config()

    # ① 最低风险等级
    if not _risk_ge(alert.get('risk_level'), rules.get('min_risk') or '高危'):
        return False, ST_BELOW, '风险等级低于通知阈值（{}）'.format(rules.get('min_risk'))

    # ② 静默时段
    if _in_quiet_hours():
        if not _risk_ge(alert.get('risk_level'), rules.get('quiet_min_risk') or '高危'):
            return False, ST_QUIET, '处于静默时段（{}），该等级未达放行标准'.format(
                rules.get('quiet_hours'))

    # ③ 收件人
    if not list_recipients(only_enabled=True):
        return False, ST_NO_RECIPIENT, '没有启用的收件人'

    # ④ SMTP 配置
    cfg = smtp_config(mask=False)
    if not cfg.get('host') or not cfg.get('sender'):
        return False, ST_NOT_CONFIGURED, 'SMTP 未配置（缺少服务器地址或发件人）'

    # ⑤ 去重
    ok, why = _passes_dedup(alert, rules)
    if not ok:
        return False, ST_DEDUPED, why

    # ⑥ 限流
    ok, why = _passes_rate_limit(rules)
    if not ok:
        return False, ST_RATE_LIMITED, why

    return True, 'ok', ''


# ============================================================================
#                              投递留痕
# ============================================================================

def log_delivery(alert, status, detail='', recipient='', latency_ms=None,
                 channel=CHANNEL_EMAIL):
    """记录一次通知投递（含被跳过的）。全部落库以便审计。"""
    try:
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO notify_log (created_at, alert_id, channel, alert_type, '
            'risk_level, source_ip, status, detail, recipient, latency_ms) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
             alert.get('id'), channel, alert.get('alert_type'),
             alert.get('risk_level'), alert.get('source_ip'),
             status, (detail or '')[:500], recipient, latency_ms)
        )
        conn.commit()
    except Exception as e:
        logger.error('通知日志写入失败: {}'.format(e))
def list_logs(limit=100, offset=0):
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            'SELECT id, created_at, alert_id, channel, alert_type, risk_level, '
            'source_ip, status, detail, recipient, latency_ms '
            'FROM notify_log ORDER BY id DESC LIMIT ? OFFSET ?', (limit, offset))
        cols = ['id', 'created_at', 'alert_id', 'channel', 'alert_type',
                'risk_level', 'source_ip', 'status', 'detail', 'recipient',
                'latency_ms']
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        conn.close()


def stats():
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) FROM notify_log')
        total = cur.fetchone()[0]
        cur.execute('SELECT status, COUNT(*) FROM notify_log GROUP BY status')
        by_status = dict(cur.fetchall())
        cur.execute('SELECT COUNT(*) FROM notify_log WHERE status = ?', (ST_SENT,))
        sent = cur.fetchone()[0]
        return {
            'total': total,
            'by_status': by_status,
            'sent': sent,
            # 被抑制的比例 = 1 - 真正投递 / 全部评估过的告警
            # 这个数字直接说明"告警疲劳防护"起了多大作用
            'suppressed': max(0, total - sent),
            'suppress_rate': round((total - sent) / total * 100, 1) if total else 0.0,
        }
    finally:
        conn.close()


# ============================================================================
#                              邮件渲染与发送
# ============================================================================

_STATUS_COLOR = {
    '高危': '#dc2626',
    '中危': '#d97706',
    '低危': '#059669',
}


def _render_subject(alerts):
    if len(alerts) == 1:
        a = alerts[0]
        return '[CyberGuard][{}] {} 来自 {}'.format(
            a.get('risk_level', ''), a.get('alert_type', ''), a.get('source_ip', ''))
    top = max(alerts, key=lambda x: RISK_ORDER.get(x.get('risk_level'), 0))
    return '[CyberGuard][{}] {} 条安全告警（最高 {}：{}）'.format(
        top.get('risk_level', ''), len(alerts),
        top.get('alert_type', ''), top.get('source_ip', ''))


def _render_text(alerts):
    lines = ['CyberGuard 安全告警通知', '=' * 46, '']
    lines.append('本次共 {} 条告警，明细如下：'.format(len(alerts)))
    lines.append('')
    for i, a in enumerate(alerts[:NOTIFY_MAX_ALERTS_PER_MAIL], 1):
        lines.append('{}. [{}] {}'.format(i, a.get('risk_level', ''), a.get('alert_type', '')))
        lines.append('   时间   : {}'.format(a.get('alert_time', '')))
        lines.append('   来源 IP: {}'.format(a.get('source_ip') or '--'))
        lines.append('   描述   : {}'.format(a.get('description') or '--'))
        lines.append('')
    rest = len(alerts) - NOTIFY_MAX_ALERTS_PER_MAIL
    if rest > 0:
        lines.append('（另有 {} 条告警未在此列出）'.format(rest))
        lines.append('')
    lines.append('-' * 46)
    lines.append('本邮件由 CyberGuard 安全运营平台自动发送，请勿直接回复。')
    lines.append('如需调整通知规则或收件人，请登录平台「通知配置」页面。')
    return '\n'.join(lines)


def _render_html(alerts):
    rows = []
    for a in alerts[:NOTIFY_MAX_ALERTS_PER_MAIL]:
        color = _STATUS_COLOR.get(a.get('risk_level'), '#64748b')
        rows.append(
            '<tr>'
            '<td style="padding:8px 10px;border-bottom:1px solid #e5e7eb;white-space:nowrap;'
            'color:#6b7280;font-size:12px">{time}</td>'
            '<td style="padding:8px 10px;border-bottom:1px solid #e5e7eb">'
            '<span style="display:inline-block;padding:1px 8px;border-radius:10px;'
            'font-size:12px;color:#fff;background:{color}">{risk}</span></td>'
            '<td style="padding:8px 10px;border-bottom:1px solid #e5e7eb;font-size:13px">'
            '<b>{atype}</b></td>'
            '<td style="padding:8px 10px;border-bottom:1px solid #e5e7eb;'
            'font-family:Consolas,Menlo,monospace;font-size:12px">{ip}</td>'
            '<td style="padding:8px 10px;border-bottom:1px solid #e5e7eb;'
            'font-size:12px;color:#4b5563">{desc}</td>'
            '</tr>'.format(
                time=html.escape(str(a.get('alert_time') or '')),
                color=color,
                risk=html.escape(str(a.get('risk_level') or '')),
                atype=html.escape(str(a.get('alert_type') or '')),
                ip=html.escape(str(a.get('source_ip') or '--')),
                desc=html.escape(str(a.get('description') or '--')),
            ))

    rest = len(alerts) - NOTIFY_MAX_ALERTS_PER_MAIL
    more = ('<p style="margin:14px 0 0;font-size:12px;color:#6b7280">'
            '（另有 {} 条告警未在此列出，请登录平台查看完整列表）</p>'.format(rest)
            if rest > 0 else '')

    top = max(alerts, key=lambda x: RISK_ORDER.get(x.get('risk_level'), 0))
    top_color = _STATUS_COLOR.get(top.get('risk_level'), '#64748b')

    return '''<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:24px;background:#f3f4f6;
             font-family:-apple-system,'Segoe UI','Microsoft YaHei',sans-serif;color:#111827">
  <div style="max-width:760px;margin:0 auto;background:#fff;border-radius:10px;
              overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,.06)">
    <div style="padding:18px 22px;background:#111827;color:#fff">
      <div style="font-size:16px;font-weight:600">CyberGuard 安全告警通知</div>
      <div style="font-size:12px;color:#9ca3af;margin-top:4px">
        本次共 {count} 条告警 · 最高等级
        <span style="color:{top_color};font-weight:600">{top_risk}</span>
      </div>
    </div>
    <div style="padding:18px 22px">
      <table style="width:100%;border-collapse:collapse">
        <thead><tr>
          <th style="text-align:left;padding:8px 10px;border-bottom:2px solid #e5e7eb;
                     font-size:12px;color:#6b7280">时间</th>
          <th style="text-align:left;padding:8px 10px;border-bottom:2px solid #e5e7eb;
                     font-size:12px;color:#6b7280">等级</th>
          <th style="text-align:left;padding:8px 10px;border-bottom:2px solid #e5e7eb;
                     font-size:12px;color:#6b7280">告警类型</th>
          <th style="text-align:left;padding:8px 10px;border-bottom:2px solid #e5e7eb;
                     font-size:12px;color:#6b7280">来源 IP</th>
          <th style="text-align:left;padding:8px 10px;border-bottom:2px solid #e5e7eb;
                     font-size:12px;color:#6b7280">描述</th>
        </tr></thead>
        <tbody>{rows}</tbody>
      </table>
      {more}
    </div>
    <div style="padding:14px 22px;background:#f9fafb;border-top:1px solid #e5e7eb;
                font-size:11px;color:#9ca3af;line-height:1.7">
      本邮件由 CyberGuard 安全运营平台自动发送，请勿直接回复。<br>
      通知内容遵循最小必要原则：仅包含判断严重性所需字段，不含完整日志与用户标识。<br>
      如需调整通知规则或收件人，请登录平台「通知配置」页面。
    </div>
  </div>
</body></html>'''.format(
        count=len(alerts), rows=''.join(rows), more=more,
        top_risk=html.escape(str(top.get('risk_level') or '')),
        top_color=top_color)


def _build_message(alerts, sender, recipients, tracking_id):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = Header(_render_subject(alerts), 'utf-8')
    msg['From'] = sender
    msg['To'] = ', '.join(recipients)
    msg['Date'] = email.utils.formatdate(localtime=True)
    msg['Message-ID'] = email.utils.make_msgid(domain='cyberguard.local')
    # 投递追踪头：便于在收件端核对"这封信确实是本系统发出的"
    msg['X-CyberGuard-Tracking-Id'] = tracking_id
    msg['X-CyberGuard-Alert-Count'] = str(len(alerts))
    msg.attach(MIMEText(_render_text(alerts), 'plain', 'utf-8'))
    msg.attach(MIMEText(_render_html(alerts), 'html', 'utf-8'))
    return msg


def _save_to_outbox(msg, tracking_id):
    """把邮件落一份 .eml 到本地存底目录。

    为什么需要它：演示或测试环境往往没有可用的 SMTP 服务器。
    有了本地存底，任何人都可以用邮件客户端直接打开 .eml 文件，
    查看真实生成的邮件内容 —— 从"日志说发了"变成"邮件就在这儿"。
    """
    try:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        outdir = os.path.join(base, NOTIFY_OUTBOX_DIR)
        os.makedirs(outdir, exist_ok=True)
        fname = '{}_{}.eml'.format(
            datetime.datetime.now().strftime('%Y%m%d-%H%M%S'), tracking_id)
        path = os.path.join(outdir, fname)
        with io.open(path, 'wb') as f:
            f.write(msg.as_bytes())
        return path
    except Exception as e:
        logger.error('邮件存底失败: {}'.format(e))
        return None


def send_email(alerts, recipients=None, purpose='alert'):
    """发送一封（聚合后的）告警邮件。

    Returns:
        (ok: bool, detail: str, latency_ms: int)
    **本函数内部捕获所有异常** —— 邮件发不出去绝不能影响主业务流程。
    """
    started = time.time()
    cfg = smtp_config(mask=False)
    if not cfg.get('host') or not cfg.get('sender'):
        return False, 'SMTP 未配置', 0

    recips = recipients
    if recips is None:
        recips = [r['email'] for r in list_recipients(only_enabled=True)]
    if not recips:
        return False, '没有启用的收件人', 0

    tracking_id = '{}-{}'.format(
        purpose, datetime.datetime.now().strftime('%H%M%S%f')[:10])

    try:
        msg = _build_message(alerts, cfg['sender'], recips, tracking_id)
        local_path = _save_to_outbox(msg, tracking_id)

        host = cfg['host']
        try:
            port = int(cfg.get('port') or 465)
        except (TypeError, ValueError):
            port = 465
        user = cfg.get('user') or ''
        password = cfg.get('password') or ''
        use_ssl = str(cfg.get('use_tls', '1')) in ('1', 'true', 'True', 'ssl')

        if use_ssl:
            server = smtplib.SMTP_SSL(host, port, timeout=NOTIFY_SMTP_TIMEOUT)
        else:
            server = smtplib.SMTP(host, port, timeout=NOTIFY_SMTP_TIMEOUT)
            server.ehlo()
            try:
                server.starttls()
                server.ehlo()
            except smtplib.SMTPException as exc:
                # 服务器不支持 STARTTLS 时继续明文发送（部分内网 SMTP 如此）。
                # 这属于可接受的降级，但要留下痕迹，便于排查"为什么没加密"。
                logger.debug("SMTP 服务器不支持 STARTTLS，降级为明文连接: %s", exc)
        try:
            if user and password:
                server.login(user, password)
            server.sendmail(cfg['sender'], recips, msg.as_string())
        finally:
            try:
                server.quit()
            except Exception as exc:
                # quit 失败不影响邮件是否已送达，但连接未正常关闭可能意味着
                # 服务端提前断链 —— 记录到 debug 以便与"投递失败"对照排查。
                logger.debug("SMTP 连接关闭异常（不影响投递结果）: %s", exc)

        latency = int((time.time() - started) * 1000)
        detail = '已投递至 {}'.format(', '.join(recips))
        if local_path:
            detail += '（本地存底：{}）'.format(os.path.basename(local_path))
        return True, detail, latency

    except Exception as e:
        latency = int((time.time() - started) * 1000)
        return False, '投递失败：{}: {}'.format(type(e).__name__, e), latency


# ============================================================================
#                              聚合与异步投递
# ============================================================================

def _worker_loop():
    """后台投递线程：做聚合缓冲 + 异步发送。

    为什么用后台线程而不是同步发送：
    SMTP 握手 + 认证 + 投递可能耗时数秒。若在告警生成的调用栈里同步发送，
    会把检测引擎与 WebSocket 推送一起拖慢 —— 而"发邮件慢"绝不该影响
    "告警什么时候出现在大屏上"。
    """
    global _pending_since
    while not _worker_stop.is_set():
        try:
            batch = None
            with _lock:
                if _pending:
                    rules = rules_config()
                    elapsed = time.time() - (_pending_since or time.time())
                    # 达到聚合窗口，或者积压过多（>10 条）立即发送
                    if elapsed >= rules.get('aggregate_seconds', 12) or len(_pending) > 10:
                        batch = list(_pending)
                        _pending.clear()
                        _pending_since = None
            if batch:
                _deliver_batch(batch)
        except Exception as e:
            logger.error('通知投递线程异常: {}'.format(e))
        _worker_stop.wait(1.0)


def start_worker():
    """启动后台投递线程（幂等）。"""
    global _worker
    if _worker and _worker.is_alive():
        return
    _worker_stop.clear()
    _worker = threading.Thread(target=_worker_loop, daemon=True,
                               name='cyberguard-notifier')
    _worker.start()
    print('告警通知投递线程已启动')


def stop_worker():
    _worker_stop.set()


def _recipients_for(alert):
    """按每条告警的风险等级筛选收件人（支持"某人只看高危"）。"""
    return [r['email'] for r in list_recipients(only_enabled=True)
            if _risk_ge(alert.get('risk_level'), r.get('min_risk') or '高危')]


def _deliver_batch(batch):
    """投递一批告警。按收件人分组：不同人可能订阅不同等级。"""
    # 按"能收到这批告警的收件人集合"分组，避免给只看高危的人发中危邮件
    groups = {}
    for alert in batch:
        for addr in _recipients_for(alert):
            groups.setdefault(addr, []).append(alert)

    all_targets = {a for al in batch for a in _recipients_for(al)}

    # 记录被规则拦下的（逐条留痕，便于审计"为什么没收到通知"）
    for alert in batch:
        if not _recipients_for(alert):
            log_delivery(alert, ST_BELOW,
                         detail='该告警等级未达任何收件人的订阅阈值')
            continue
        if not all_targets:
            continue

    if not groups:
        return

    # 合并所有收件人 -> 统一发送一封（收件人作为整体，避免重复投递同一批内容）
    recipients = sorted(groups.keys())
    merged = sorted(batch, key=lambda x: RISK_ORDER.get(x.get('risk_level'), 0),
                    reverse=True)
    ok, detail, latency = send_email(merged, recipients=recipients)
    if ok:
        _mark_sent()
    for alert in batch:
        log_delivery(alert, ST_SENT if ok else ST_FAILED, detail=detail,
                     recipient=', '.join(recipients), latency_ms=latency)


def notify_alert(alert):
    """对一条告警执行完整的通知流程（规则评估 → 入聚合缓冲）。

    该函数由告警落库链路调用。**必须快速返回**：
    规则评估是轻量的，真正的网络投递交给后台线程。

    Args:
        alert: dict，含 id / alert_type / risk_level / source_ip /
               description / alert_time
    """
    global _pending_since          # 模块级变量，函数内赋值必须声明 global
    try:
        ok, status, why = evaluate(alert)
        if not ok:
            log_delivery(alert, status, detail=why)
            return status
        with _lock:
            _pending.append(alert)
            if _pending_since is None:
                _pending_since = time.time()
        return 'queued'
    except Exception as e:
        # 通知系统自身的任何异常都不能影响告警主流程
        logger.error('通知评估异常: {}'.format(e))
        return 'error'
