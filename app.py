"""
==============================================================================
  CyberGuard DDoS 防护监控平台 — Flask 主应用入口
==============================================================================
  本文件是项目的服务端核心，负责：
  1. Flask 应用初始化、WebSocket 服务配置
  2. 页面路由定义（6 个功能页面）
  3. RESTful API 接口（暴力破解 + DDoS 两大模块）
  4. DDoS 模拟器后台线程管理与实时数据广播
  5. WebSocket 事件处理（连接/断开/全量状态推送）

  架构说明：
  - Web 框架：Flask（路由 + 模板渲染）
  - 实时通信：Flask-SocketIO + eventlet（WebSocket 双向推送）
  - 异步任务：后台线程 + eventlet.sleep（DDoS 模拟循环）
  - 数据持久化：SQLite（通过 utils/db_helper.py 操作）
  - 攻击模拟：utils/ddos_simulator.py（纯内存状态机）

  API 设计原则：
  - 页面路由返回 HTML 模板，前后端分离渲染
  - 数据 API 返回 JSON，支持前端 AJAX/WebSocket 双通道获取
  - 导出 API 返回 Excel 二进制流（openpyxl 引擎）

  运行安全说明（演示/答辩环境）：
  - 仅监听 127.0.0.1，不对局域网暴露
  - debug=False，避免 Werkzeug 调试器成为 RCE 入口
  - CORS 白名单收敛为本机来源
  - 演示接口 /api/demo/* 仅在 DEMO_MODE=1 时注册，默认关闭
==============================================================================
"""

import os
import logging

# ---- 日志基础设施 ----
# 统一由 logging 输出错误信息，而不是散落的 print：
#   · 有级别、有时间戳、可重定向到文件
#   · 启动横幅与用户可读进度仍用 print（它们是产品输出，不是日志）
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("cyberguard")

import sys

# Windows 控制台默认 GBK，无法编码 emoji 与部分符号，会让 print() 抛
# UnicodeEncodeError 并中断检测/初始化流程。统一把标准输出切到 UTF-8。
# 注意：这里的 except 是**刻意静默**的 —— 走到这条分支说明解释器没有
# reconfigure（旧版本或非 TextIOWrapper），此时保持原编码即为正确行为；
# 而且 logging 也写往同一个流，在此处记日志只会引发二次失败。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

from flask import Flask, render_template, jsonify, request, send_file, session, redirect, url_for
from flask_socketio import SocketIO, emit
from utils.db_helper import (
    init_db, get_all_login_logs, get_all_alerts, get_all_blacklist,
    update_alert_status, add_to_blacklist, remove_from_blacklist,
    alert_exists, insert_alert,
    query_login_logs,      # SQL 层筛选 + 分页查询（/api/logs）
    get_alert_summary,     # SQL 层聚合统计（/api/alerts/summary）
)
from utils.auth import (
    ROLE_ADMIN, ROLE_VIEWER, ROLE_LABELS, ROLE_PERMISSIONS,
    current_user, is_admin, login_session, logout_session,
    issue_csrf_token, csrf_ok, require_role, require_login,
    get_all_users, update_user, delete_user, count_admins,
    init_auth_db, create_user, verify_user,
)
from utils.log_generator import generate_mock_logs
from utils.detector import run_all_detections
from utils.ddos_simulator import (
    simulate_tick, get_current_state, reset_state,
    trigger_wave, get_wave_status,
)
from utils import host_metrics
from utils import notifier
import pandas as pd
from io import BytesIO
import sqlite3
import secrets
import eventlet
import webbrowser
import threading
import time
import random
from config import DATABASE_PATH
from datetime import datetime, timedelta

# ============================================================================
#                           Flask 应用初始化
# ============================================================================
app = Flask(__name__)

# 加载全局配置（数据库路径、检测规则、攻击类型定义等）
import config as app_config
app.config.from_object(app_config)

# 会话密钥：优先环境变量；未配置则生成一次性随机密钥。
# 不再使用硬编码兜底值——可预测的会话密钥等于没有会话安全。
if not app.config.get("SECRET_KEY"):
    app.config["SECRET_KEY"] = secrets.token_hex(32)
    print("⚠️  未检测到 SECRET_KEY 环境变量，已生成一次性随机密钥（重启后旧会话失效）")
app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
app.config.setdefault("PERMANENT_SESSION_LIFETIME", timedelta(hours=8))

# 初始化 Flask-SocketIO — 使用 eventlet 异步模式支持 WebSocket 长连接
# cors_allowed_origins="*" 允许前端跨域访问（开发环境简化配置）
# ping_timeout/ping_interval 用于检测断线并自动重连
socketio = SocketIO(
    app,
    cors_allowed_origins=[
        "http://127.0.0.1:5000", "http://localhost:5000",
    ],
    async_mode='eventlet',
    ping_timeout=30,
    ping_interval=15,
    logger=False,          # 生产环境关闭调试日志
    engineio_logger=False
)

# 应用启动时自动初始化数据库表结构（幂等操作，重复执行安全）
init_db()

# 初始化认证模块（users 表 + 默认管理员账户）
init_auth_db()

# 初始化通知模块（notify_config / notify_recipients / notify_log 三张表）
notifier.init_notify_db()
notifier.start_worker()


# ============================================================================
#              通知钩子：告警落库后自动进入通知流程
# ============================================================================
# 做法：把 db_helper.insert_alert 包装一层，在写入成功后取出该行并交给通知模块。
#
# 为什么用包装而不是在每个调用点手工添加：
# 告警来源有两处 —— 5 条登录检测规则（utils/detector.py）
# 与 DDoS 沙箱告警（app._persist_ddos_alert）。若逐点添加，
# 将来新增任何一种告警都会漏掉通知；包装在写入这一层则天然全覆盖。
_ORIGINAL_INSERT_ALERT = insert_alert


def _insert_alert_with_notify(*args, **kwargs):
    """写入告警并在成功后触发通知评估。

    注意：通知评估是**轻量**的（只做规则判断与入队），
    真正的 SMTP 投递由 notifier 的后台线程完成 ——
    发邮件慢绝不该阻塞告警生成与 WebSocket 推送。
    """
    row_id = _ORIGINAL_INSERT_ALERT(*args, **kwargs)
    try:
        if row_id:
            conn = sqlite3.connect(DATABASE_PATH, timeout=5)
            cur = conn.cursor()
            cur.execute(
                'SELECT id, alert_time, alert_type, risk_level, ip_address, '
                'description FROM alerts WHERE id = ?', (row_id,))
            row = cur.fetchone()
            conn.close()
            if row:
                notifier.notify_alert({
                    'id': row[0],
                    'alert_time': row[1],
                    'alert_type': row[2],
                    'risk_level': row[3],
                    'source_ip': row[4],
                    'description': row[5],
                })
    except Exception as e:
        # 通知环节的任何异常都不能影响告警落库的结果
        logger.exception('告警通知触发失败: %s', e)
    return row_id


insert_alert = _insert_alert_with_notify

# 注册认证路由蓝图（登录 / 注册 / 登出 / 用户管理）
from utils.auth_routes import auth_bp
app.register_blueprint(auth_bp)

# 注册告警通知路由蓝图（通知配置页 + 相关 API，全部仅管理员）
from utils.notify_routes import notify_bp
app.register_blueprint(notify_bp)


# ============================================================================
#                 全局请求钩子：黑名单拦截 + CSRF 校验 + 模板上下文
# ============================================================================
# 说明：以下三个钩子是本系统「安全能力」真正落地的地方——
# 黑名单不再只是数据库里的一条记录，而是会对来自该 IP 的请求返回 403。

# 本机回环地址：永不拦截。否则演示时一旦把 127.0.0.1 加进黑名单，
# 会把自己锁在系统外面（安全设计必须考虑可用性与自救通路）。
_LOOPBACK_IPS = {"127.0.0.1", "::1", "localhost", ""}

# 明确豁免 CSRF 校验的端点：
#  - auth.login / auth.register 是未登录状态下的表单提交，由表单自身承载
#  - 演示接口 /api/demo/* 已用 DEMO_MODE 开关 + 本机来源双重限制
_CSRF_EXEMPT_ENDPOINTS = {"auth.login", "auth.register"}
_CSRF_EXEMPT_PREFIXES = ("/api/demo/",)


def _is_blacklisted(ip):
    """查询 IP 是否处于有效封禁期内（含过期时间判断）。

    修复点：expire_time 字段此前只写不读，封禁永不到期。
    现在按 expire_time 过滤，过期的封禁记录不再拦截。
    """
    if not ip or ip in _LOOPBACK_IPS:
        return False
    try:
        conn = sqlite3.connect(DATABASE_PATH, timeout=5)
        cur = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cur.execute(
            "SELECT COUNT(*) FROM ip_blacklist "
            "WHERE ip_address = ? AND (expire_time IS NULL OR expire_time > ?)",
            (ip, now)
        )
        hit = cur.fetchone()[0] > 0
        conn.close()
        return hit
    except sqlite3.Error:
        # 数据库异常时放行，避免因存储故障导致整站不可用（可用性优先）
        return False


@app.before_request
def _enforce_blacklist_and_csrf():
    """统一入口防护：黑名单拦截 + 写操作 CSRF 校验。"""
    path = request.path or ""

    # ---- 1) 黑名单拦截 ----
    # 静态资源放行，保证被拦截者仍能看到「你已被封禁」的提示页而不是白屏
    if not path.startswith("/static/"):
        if _is_blacklisted((request.remote_addr or "").strip()):
            if request.path.startswith("/api/"):
                return jsonify({
                    "status": "blocked",
                    "message": "您的 IP 已被安全策略封禁，请联系管理员",
                }), 403
            return render_template("blocked.html", ip=request.remote_addr), 403

    # ---- 2) CSRF 校验（所有写操作）----
    # 注意：仅对**已登录会话**校验。未登录的写请求应当由权限守卫返回 401，
    # 而不是在这里先返回 400 —— 否则匿名调用者看到的是"CSRF 校验失败"，
    # 既误导调用方，也掩盖了真实的鉴权语义。
    if (request.method in ("POST", "PUT", "PATCH", "DELETE")
            and session.get("uid")):
        endpoint = (request.endpoint or "")
        if (endpoint not in _CSRF_EXEMPT_ENDPOINTS
                and not path.startswith(_CSRF_EXEMPT_PREFIXES)):
            if not csrf_ok():
                if path.startswith("/api/"):
                    return jsonify({"status": "error", "message": "CSRF 校验失败，请刷新页面重试"}), 400
                return render_template("403.html"), 400

    return None


@app.before_request
def _mark_request_start():
    """记录请求开始时间，供 after_request 计算真实耗时。"""
    from flask import g
    g._cg_t0 = time.perf_counter()


# ============================================================================
#                  DDoS 告警落库（统一两套告警体系）
# ============================================================================

def _persist_ddos_alert(attack):
    """把沙箱产生的 DDoS 攻击告警写入 alerts 表。

    修复的问题：DDoS 告警原先只通过 WebSocket 推送到前端弹窗，
    从未落库 —— 结果是「实时告警弹窗」与「告警管理」页两处数据完全对不上，
    弹窗里看到的告警在列表里根本查不到。

    现在统一写入同一张 alerts 表，并通过 alert_type 前缀 ``DDoS:``
    与登录类告警区分来源，前端据此做筛选与展示。

    写入策略：
    - 同一来源 IP + 同一攻击类型在 30 分钟内只落库一次，避免告警风暴
      （突袭期速率可达 70 个/分钟，若不做去重会瞬间淹没告警表）
    - 复用 db_helper.alert_exists 的按类型+IP 去重能力
    """
    try:
        ip = attack.get('source_ip')
        type_name = attack.get('type_name') or '未知'
        alert_type = 'DDoS: {}'.format(type_name)

        # 30 分钟窗口内同一 IP + 同一类型只记一次
        if alert_exists(alert_type, ip_address=ip, within_hours=0.5):
            return

        risk = '高危' if attack.get('risk') == '高危' else '中危'
        insert_alert(
            alert_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            alert_type=alert_type,
            risk_level=risk,
            ip_address=ip,
            username=None,
            attempt_count=1,
            description=(
                "DDoS 攻击事件 {} | 类型 {} | 来源 {} {} | 目标端口 {} | "
                "峰值 {} Mbps | 处置 {}".format(
                    attack.get('id', '--'),
                    type_name,
                    attack.get('source_country', '--'),
                    ip,
                    attack.get('target_port', '--'),
                    attack.get('bandwidth_mbps', 0),
                    attack.get('status', '--'),
                )
            ),
        )
    except Exception as e:
        # 落库失败不能影响实时推送
        logger.exception('DDoS 告警落库失败: %s', e)


@app.after_request
def _record_request_cost(response):
    """把每次请求的真实耗时记入滚动窗口。

    用途：替换攻击链页原先那个「2~7 秒之间的随机数」。
    它每次刷新都在跳，不属于任何测量值；这里改为真实测量结果。
    """
    from flask import g
    t0 = getattr(g, '_cg_t0', None)
    if t0 is not None:
        host_metrics.record_request((time.perf_counter() - t0) * 1000)
    return response


@app.context_processor
def _inject_identity():
    """向所有模板注入当前登录身份、权限集合与 CSRF 令牌。

    前端据此隐藏无权限的按钮；真正的权限判定始终在服务端。
    """
    user = current_user()
    role = user["role"] if user else None
    return {
        "current_user": user,
        "is_admin": role == ROLE_ADMIN,
        "role_label": ROLE_LABELS.get(role, ""),
        "permissions": ROLE_PERMISSIONS.get(role, {}) if user else {},
        "csrf_token": issue_csrf_token() if user else "",
    }


# ============================================================================
#                          全局错误页
# ============================================================================
# 为什么需要：
#   此前项目没有任何 @app.errorhandler，访问不存在的路径会落到 Flask 默认的
#   英文错误页（"Not Found / The requested URL was not found"），与整站视觉割裂，
#   演示时误点一个失效链接就会露馅。
#
# 约定：/api/ 前缀的请求仍返回 JSON（前端按 JSON 解析，拿到 HTML 会报解析错误），
#       页面请求才渲染错误模板。


def _wants_json() -> bool:
    """判断当前请求是否应当得到 JSON 错误响应。"""
    return (request.path or "").startswith("/api/")


@app.errorhandler(404)
def _handle_404(err):
    """路由不存在。"""
    if _wants_json():
        return jsonify({"status": "error", "message": "接口不存在"}), 404
    return render_template("404.html", request_path=request.path), 404


@app.errorhandler(405)
def _handle_405(err):
    """HTTP 方法不允许（例如对 POST-only 接口发 GET）。"""
    if _wants_json():
        return jsonify({"status": "error", "message": "请求方法不被允许"}), 405
    return render_template("404.html", request_path=request.path), 405


@app.errorhandler(500)
def _handle_500(err):
    """未捕获的服务器异常。

    安全说明：异常详情**只写入日志**，绝不在页面上回显 ——
    回显 traceback 会泄露文件路径与内部实现，是常见的信息泄露源。
    """
    logger.exception("未捕获的服务器异常: %s %s", request.method, request.path)
    if _wants_json():
        return jsonify({"status": "error", "message": "服务器内部错误"}), 500
    return render_template("500.html", request_path=request.path), 500

# ============================================================================
#                       DDoS 模拟器后台线程管理
# ============================================================================
# 模拟器状态标志和线程引用
_simulator_running = False      # 控制循环的开关
_simulator_thread = None        # 后台线程对象引用


def _ddos_simulation_loop():
    """
    DDoS 模拟器主循环 — 在后台线程中持续运行

    工作流程：
    1. 每 1.5 秒调用 simulate_tick() 生成一次模拟数据
    2. 获取当前完整状态快照
    3. 通过 WebSocket 向所有连接的客户端广播实时数据
    4. 每隔 5 秒检查是否有新攻击事件，触发告警推送

    推送数据结构：
    - stats:       核心统计指标（带宽、攻击数、防护率等）
    - traffic:     最近一次流量数据点
    - attacks:     当前活跃攻击列表（Top 5）
    - timeline:    最近 3 条攻击时间线事件
    - attack_alert:攻击告警事件（独立事件，触发前端弹窗）
    """
    global _simulator_running
    _simulator_running = True
    last_alert_check = 0  # 上次告警检查的时间戳

    while _simulator_running:
        try:
            # 步骤1：执行一次模拟 tick，生成新的流量和攻击数据
            # 注意：tick 只在这里（后台线程）推进，HTTP 接口不再调用它，
            # 否则前端轮询会加速状态推进、打乱攻击浪潮的节奏。
            simulate_tick()
            # 与攻击模拟同一节拍采样真实主机指标（CPU/内存/磁盘IO/网卡吞吐）。
            # 这些是 psutil 读取的操作系统真实计数器，不是派生值。
            host_metrics.sample()
            state = get_current_state()

            # 步骤2：广播实时数据更新（全量客户端）
            socketio.emit('ddos_update', {
                'stats': state['stats'],
                'traffic': state['traffic_history'][-1] if state['traffic_history'] else None,
                'attacks': state['current_attacks'][:5],
                'timeline': state['timeline'][-3:] if state['timeline'] else [],
                'wave': state.get('wave'),          # 浪潮阶段，供前端徽章实时更新
            })

            # 步骤3：检查是否有新攻击需要独立告警推送
            # 只推送"攻击中"和"检测中"状态的活跃攻击
            active_attacks = [
                a for a in state['current_attacks']
                if a['status'] in ['攻击中', '检测中']
            ]
            if active_attacks and time.time() - last_alert_check > 5:
                # 每次最多推送 2 个告警，避免通知轰炸
                for attack in active_attacks[:2]:
                    socketio.emit('attack_alert', {
                        'id': attack['id'],
                        'type': attack['type_name'],
                        'source': attack['source_ip'],
                        'country': attack['source_country'],
                        'bandwidth': attack['bandwidth_mbps'],
                        'risk': attack['risk'],
                        'timestamp': datetime.now().strftime('%H:%M:%S'),
                        'message': (
                            f"检测到 {attack['type_name']} 攻击 | "
                            f"来源: {attack['source_country']} | "
                            f"流量: {attack['bandwidth_mbps']}Mbps"
                        )
                    })
                    # 同步落库到 alerts 表 —— 修复"两套告警体系互不相通"的问题。
                    # 原先 DDoS 告警只走 WebSocket 弹窗，导致弹窗里的告警
                    # 在「告警管理」页完全查不到，两处数据对不上。
                    # 现在统一写入同一张表，前端通过 alert_type 前缀 "DDoS:" 区分来源。
                    _persist_ddos_alert(attack)
                last_alert_check = time.time()

            # eventlet.sleep 是非阻塞的，不占用 CPU
            eventlet.sleep(1.5)

        except Exception as e:
            logger.exception('模拟器异常: %s', e)
            eventlet.sleep(3)  # 异常时等待较长时间再重试


def start_simulator():
    """
    启动 DDoS 模拟器后台线程

    使用 socketio.start_background_task 而非 threading.Thread，
    确保在 Flask-SocketIO 的 eventlet 事件循环中运行
    """
    global _simulator_thread, _simulator_running
    if _simulator_running:
        return  # 防止重复启动
    _simulator_running = True
    _simulator_thread = socketio.start_background_task(_ddos_simulation_loop)
    print("DDoS 模拟器已启动")


def stop_simulator():
    """停止 DDoS 模拟器 — 设置标志位让循环自然退出"""
    global _simulator_running
    _simulator_running = False
    print("DDoS 模拟器已停止")


# ============================================================================
#                         WebSocket 事件处理
# ============================================================================

@socketio.on('connect')
def handle_connect():
    # 安全设计：实时态势数据属内部信息，未登录连接一律拒绝（返回 False 中止握手）
    if not current_user():
        logger.warning('拒绝未登录的 WebSocket 连接')
        return False
    """
    客户端 WebSocket 连接成功事件

    发送一条欢迎消息确认连接建立，包含时间戳方便调试
    前端收到 'connected' 事件后会触发 'request_full_state' 请求全量数据
    """
    emit('connected', {
        'message': '已连接到 DDoS 防护监控系统',
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })


@socketio.on('disconnect')
def handle_disconnect():
    """客户端断开连接事件 — 当前无需清理操作，预留扩展点"""
    pass


@socketio.on('request_full_state')
def handle_full_state():
    if not current_user():
        return
    """
    客户端请求全量状态快照

    用于页面首次加载或手动刷新时获取完整数据
    返回包含流量历史、攻击列表、攻击链、地理数据等的完整状态对象
    """
    state = get_current_state()
    emit('full_state', state)


# ============================================================================
#                          页面路由（6 个功能页面）
# ============================================================================

@app.route('/')
@require_login(api=False)
def index():
    """首页 — 全维度态势感知大屏（流量趋势、攻击分布、系统健康度）"""
    return render_template('index.html')


@app.route('/logs')
@require_login(api=False)
def logs():
    """登录日志页面 — 暴力破解日志的查询、筛选、导出"""
    return render_template('logs.html')


@app.route('/alerts')
@require_login(api=False)
def alerts():
    """告警管理页面 — 安全告警的筛选、处理、导出"""
    return render_template('alerts.html')


@app.route('/blacklist')
@require_login(api=False)
def blacklist_page():
    """黑名单管理页面 — IP 封禁的添加、查看、解除"""
    return render_template('blacklist.html')




@app.route('/heatmap')
@require_login(api=False)
def heatmap_page():
    """全球攻击热力地图 — 攻击来源的地理分布可视化"""
    return render_template('heatmap.html')


@app.route('/attack-chain')
@require_login(api=False)
def attack_chain_page():
    """攻击链分析页面 — 桑基图 + TOP10 攻击者 + 攻击时间线"""
    return render_template('attack_chain.html')


# ============================================================================
#                 暴力破解模块 API（登录日志 + 告警 + 黑名单）
# ============================================================================

@app.route('/api/logs')
@require_login()
def api_logs():
    """分页获取登录日志（筛选与分页均在 SQL 层完成）。

    查询参数（均为可选）：
    - page:       页码，从 1 开始（默认 1）
    - page_size:  每页条数（默认 50，上限 500）
    - ip:         按 IP 模糊匹配
    - username:   按用户名模糊匹配
    - success:    按登录结果筛选（true/false）

    返回：{items, total, page, page_size, pages}

    改动说明：
      原实现 `return jsonify(get_all_login_logs())` 一次性返回全表，
      实测约 1700 条 / 260KB，且随演示生成的日志持续增长。
      现在默认只返回一页，客户端通过 page/page_size 翻页。
    """
    result = query_login_logs(
        ip=request.args.get('ip', ''),
        username=request.args.get('username', ''),
        success=request.args.get('success', ''),
        page=request.args.get('page', 1),
        page_size=request.args.get('page_size', 50),
    )
    return jsonify(result)


@app.route('/api/logs/filter')
@require_login()
def api_filter_logs():
    """按条件筛选登录日志 —— 现已在 SQL 层通过参数化 WHERE 实现。

    查询参数（均为可选）：
    - ip:       按 IP 地址模糊匹配
    - username: 按用户名模糊匹配
    - success:  按登录结果筛选（true/false）
    - page / page_size: 分页

    保留此路由是为了向后兼容。它现在与 /api/logs 等价 ——
    两者调用同一个 SQL 层查询函数，不再存在"一个真筛选、一个假筛选"的差异。

    历史问题：本路由的文档字符串原先写着"后端在 SQL 层做 WHERE 筛选"，
    但实际实现是把全量日志取进内存后用 Python 循环过滤，注释与实现相反。
    现已改为真正的 SQL 层筛选，注释与实现一致。
    """
    result = query_login_logs(
        ip=request.args.get('ip', ''),
        username=request.args.get('username', ''),
        success=request.args.get('success', ''),
        page=request.args.get('page', 1),
        page_size=request.args.get('page_size', 50),
    )
    return jsonify(result)


@app.route('/api/generate_logs', methods=['POST'])
@require_role(ROLE_ADMIN)
def api_generate_logs():
    """
    生成 1000 条模拟登录日志

    包含 800 条正常日志 + 200 条攻击日志
    用于演示暴力破解检测规则的触发效果

    ⚠ 必须限定 POST：
    本接口会向 login_logs 写入 1000 行，属于**变更状态**的操作。
    若沿用默认 GET，则它不在全站 CSRF 校验范围内
    （app.py 的 _enforce_blacklist_and_csrf 只检查 POST/PUT/PATCH/DELETE），
    管理员已登录时任何第三方页面用 <img src="..."> 即可触发写入。
    """
    generate_mock_logs(1000)
    return jsonify({"status": "success", "message": "模拟日志生成完成"})


@app.route('/api/alerts')
@require_login()
def api_alerts():
    """获取全部告警记录（按告警时间倒序）"""
    return jsonify(get_all_alerts())


@app.route('/api/alerts/summary')
@require_login()
def api_alerts_summary():
    """告警的聚合统计（供态势大屏使用）。

    为什么单独开这个接口：
      大屏只需要 4 个计数与规则 TOP3，原先却拉取 /api/alerts 的全量记录
      （实测 3094 条、约 1MB）到浏览器里 filter，每 30 秒一次。
      这里在 SQL 层 GROUP BY，响应约几百字节 —— 数量级差别。

    查询参数：
      hours  只看最近多少小时（可选）。大屏的「最近 24 小时 / 7 天」筛选
             传对应的 24 / 168；不传则统计全部。
    """
    hours = request.args.get('hours', type=float)
    return jsonify(get_alert_summary(hours))


@app.route('/api/alerts/update/<int:alert_id>', methods=['POST'])
@require_role(ROLE_ADMIN)
def api_update_alert(alert_id):
    """
    更新告警处理状态

    路径参数：
    - alert_id: 告警记录 ID

    请求体 JSON：
    - status: 处理状态（已处理/误报/忽略）
    - note:   处理备注（可选）
    """
    data = request.get_json()
    update_alert_status(
        alert_id,
        data.get('status', '已处理'),
        data.get('note', '')
    )
    return jsonify({"status": "success"})


@app.route('/api/alerts/export')
@require_login()
def api_export_alerts():
    """
    导出告警记录为 Excel 文件

    技术实现：
    - 使用 pandas DataFrame 构建表格
    - openpyxl 作为 Excel 写入引擎
    - 返回二进制流（BytesIO）作为文件下载
    - 文件名包含时间戳避免覆盖
    """
    alerts = get_all_alerts()
    # 构建 DataFrame，指定列名
    df = pd.DataFrame(alerts, columns=[
        'ID', '告警时间', '告警类型', '风险等级', '攻击IP',
        '用户名', '尝试次数', '描述', '状态', '处理备注', '创建时间'
    ])
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='告警记录')
    output.seek(0)
    return send_file(
        output,
        as_attachment=True,
        download_name=f"告警记录_{pd.Timestamp.now().strftime('%Y%m%d%H%M%S')}.xlsx"
    )


@app.route('/api/logs/export')
@require_login()
def api_export_logs():
    """
    导出登录日志为 Excel 文件

    实现方式与告警导出相同，列名不同
    """
    logs = get_all_login_logs()
    df = pd.DataFrame(logs, columns=[
        'ID', '时间', 'IP地址', '用户名', 'UserAgent', '登录成功', '创建时间'
    ])
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='登录日志')
    output.seek(0)
    return send_file(
        output,
        as_attachment=True,
        download_name=f"登录日志_{pd.Timestamp.now().strftime('%Y%m%d%H%M%S')}.xlsx"
    )


@app.route('/api/run_detection', methods=['POST'])
@require_role(ROLE_ADMIN)
def api_run_detection():
    """
    手动触发暴力破解检测引擎

    依次执行 5 条检测规则：
    1. IP 高频失败攻击
    2. 账号多 IP 攻击
    3. 高频失败+零星成功攻击
    4. 字典攻击
    5. 慢速暴力破解

    ⚠ 必须限定 POST：检测会写入 alerts 表并自动封禁 IP，属变更状态操作。
    沿用 GET 会绕过全站 CSRF 校验（见 _enforce_blacklist_and_csrf）。
    """
    run_all_detections()
    return jsonify({"status": "success", "message": "检测完成"})


@app.route('/api/blacklist')
@require_login()
def api_blacklist():
    """获取全部 IP 黑名单记录"""
    return jsonify(get_all_blacklist())


@app.route('/api/blacklist/add', methods=['POST'])
@require_role(ROLE_ADMIN)
def api_add_blacklist():
    """
    手动添加 IP 到黑名单

    请求体 JSON：
    - ip:     IP 地址（必填）
    - reason: 封禁原因（可选，默认"手动添加"）
    - hours:  封禁时长（可选，默认 24 小时）
    """
    data = request.get_json()
    ip = data.get('ip', '').strip()
    reason = data.get('reason', '手动添加')
    hours = int(data.get('hours', 24))

    # 输入校验：IP 不能为空
    if not ip:
        return jsonify({"status": "error", "message": "IP地址不能为空"}), 400

    success = add_to_blacklist(ip, reason, hours)
    if success:
        return jsonify({"status": "success", "message": "添加成功"})
    return jsonify({"status": "exists", "message": "IP已在黑名单中"})


@app.route('/api/blacklist/remove/<int:blacklist_id>', methods=['POST'])
@require_role(ROLE_ADMIN)
def api_remove_blacklist(blacklist_id):
    """
    从黑名单中移除 IP

    先通过 ID 查询对应的 IP 地址，再执行删除操作
    注意：此处直接操作数据库是为了通过 ID 精确查找 IP，
    复用 db_helper 的 remove_from_blacklist 函数完成实际删除
    """
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT ip_address FROM ip_blacklist WHERE id = ?', (blacklist_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "记录不存在"}), 404

    result = remove_from_blacklist(row[0])
    conn.close()
    return jsonify({"status": "success" if result else "error"})


@app.route('/api/stats')
@require_login()
def api_stats():
    """
    获取暴力破解模块的统计摘要数据

    返回内容：
    - 总日志数、总告警数、高危告警数、已封禁 IP 数
    - 24 小时告警趋势（按 6 个时间段分布）
    - 风险分布（高危/中危/低危占比）
    - 告警类型分布
    - Top 10 攻击 IP

    用途：为首页态势感知提供数据
    """
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # 基础计数
    cursor.execute('SELECT COUNT(*) FROM login_logs')
    total_logs = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM alerts')
    total_alerts = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE risk_level='高危'")
    high_risk = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM ip_blacklist')
    blocked_ips = cursor.fetchone()[0]

    # 24 小时告警趋势 — 按小时分组后聚合到 6 个时间段
    since_24h = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "SELECT strftime('%H', alert_time) as hour, COUNT(*) FROM alerts "
        "WHERE alert_time >= ? GROUP BY hour ORDER BY hour",
        (since_24h,)
    )
    trend_rows = cursor.fetchall()

    # 预定义 6 个时间段标签（每 4 小时一个区间）
    trend_labels = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00']
    trend_data = {label: 0 for label in trend_labels}
    for hour_str, count in trend_rows:
        h = int(hour_str)
        if h < 4:
            trend_data['00:00'] += count
        elif h < 8:
            trend_data['04:00'] += count
        elif h < 12:
            trend_data['08:00'] += count
        elif h < 16:
            trend_data['12:00'] += count
        elif h < 20:
            trend_data['16:00'] += count
        else:
            trend_data['20:00'] += count

    # 风险等级分布
    risk_dist = {}
    cursor.execute("SELECT risk_level, COUNT(*) FROM alerts GROUP BY risk_level")
    for level, count in cursor.fetchall():
        risk_dist[level] = count

    # 告警类型分布
    type_dist = {}
    cursor.execute("SELECT alert_type, COUNT(*) FROM alerts GROUP BY alert_type")
    for atype, count in cursor.fetchall():
        type_dist[atype] = count

    # Top 10 攻击 IP
    cursor.execute(
        "SELECT ip_address, COUNT(*) as cnt FROM alerts "
        "WHERE ip_address IS NOT NULL "
        "GROUP BY ip_address ORDER BY cnt DESC LIMIT 10"
    )
    top_ips = [{"ip": row[0], "count": row[1]} for row in cursor.fetchall()]

    conn.close()

    return jsonify({
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "high_risk": high_risk,
        "blocked_ips": blocked_ips,
        "trend": {"labels": trend_labels, "data": list(trend_data.values())},
        "risk_distribution": risk_dist,
        "alert_types": type_dist,
        "top_ips": top_ips
    })


# ============================================================================
#                   DDoS 防护监控模块 API
# ============================================================================
# 每个 API 的设计理念：
# 1. 获取当前状态快照（纯读取）
# 2. 返回前端所需的数据子集
#
# 已修复（P1-5）：原实现在每个 GET 接口里调用 simulate_tick()，
# 违反 HTTP 幂等性 —— 前端轮询本身会推进服务端状态，
# 多开几个标签页攻击生成速率就会成倍增长，攻击浪潮的节奏会被完全打乱。
# 现在 tick 只由后台线程每 1.5 秒推进，HTTP 接口是纯只读的。

@app.route('/api/host')
@require_login()
def api_host_metrics():
    """真实主机资源指标（psutil 采集）。

    与 /api/ddos/* 的边界：这里的数据来自操作系统真实计数器，
    攻击态势数据则来自内存沙箱。两者在界面上使用不同的来源徽章区分。
    """
    return jsonify(host_metrics.snapshot())


@app.route('/api/ddos/state')
@require_login()
def api_ddos_state():
    """
    获取完整 DDoS 监控状态

    返回流量历史、攻击列表、攻击链、地理数据、统计信息等全部字段
    是前端初始化时请求的核心接口
    """
    state = get_current_state()
    # 附带真实主机指标：攻击态势（沙箱）与主机资源（真实）并排展示，
    # 但来源不同，前端分别标注。
    state['host'] = host_metrics.snapshot()
    return jsonify(state)


@app.route('/api/ddos/attack-chain')
@require_login()
def api_ddos_attack_chain():
    """
    获取攻击链数据 + TOP 攻击者

    攻击链数据结构（桑基图输入）：
    - chains: 每个攻击事件的 源IP→攻击类型→目标端口→防护节点→结果 流向
    - top_attackers: 按带宽排序的 TOP10 攻击者列表
    - mitigation_nodes: 清洗节点（含经纬度）—— 3D 地球需要它来画链路终点

    说明：mitigation_nodes 原先只在 /api/ddos/geo 返回。攻击链页要画地球，
    需要节点坐标，而为了一个字段再发一次请求并不划算（等于把同一份
    模拟状态的快照取两遍，两次之间状态还可能变化，导致地球与榜单不一致）。
    因此在这里一并返回，保证本页所有可视化来自同一次快照。
    """
    state = get_current_state()
    return jsonify({
        'chains': state['attack_chains'],
        'top_attackers': state['top_attackers'],
        'mitigation_nodes': state['mitigation_nodes'],
    })


@app.route('/api/ddos/geo')
@require_login()
def api_ddos_geo():
    """
    获取全球攻击地理数据

    返回：
    - geo_data: 每个攻击来源的经纬度、国家、城市、带宽等信息
    - mitigation_nodes: 防护节点的经纬度和清洗能力
    """
    state = get_current_state()
    return jsonify({
        'geo_data': state['geo_data'],
        'mitigation_nodes': state['mitigation_nodes']
    })


@app.route('/api/ddos/timeline')
@require_login()
def api_ddos_timeline():
    """
    获取攻击事件时间线

    每条记录包含时间、攻击类型、来源 IP、状态、带宽
    用于时间序列柱状图渲染
    """
    state = get_current_state()
    return jsonify(state['timeline'])


@app.route('/api/ddos/reset', methods=['POST'])
@require_role(ROLE_ADMIN)
def api_ddos_reset():
    """
    重置 DDoS 模拟状态

    清空所有模拟数据，恢复初始状态
    用于演示重置场景

    ⚠ 必须限定 POST：本接口会清空全部模拟状态，属变更状态操作。
    沿用 GET 会绕过全站 CSRF 校验（见 _enforce_blacklist_and_csrf）。
    """
    return jsonify(reset_state())


@app.route('/docs/compliance')
@require_login(api=False)
def docs_compliance():
    """在浏览器中展示「安全与合规声明」。

    合规透明：本作品涉及攻击行为模拟，需要明确声明攻击源使用 RFC 5737 保留段、
    模拟器不产生真实报文、以及不进行任何扫描/利用行为。
    """
    root = os.path.dirname(os.path.abspath(__file__))
    md_path = os.path.join(root, 'docs', '安全与合规声明.md')
    try:
        with open(md_path, encoding='utf-8') as f:
            md = f.read()
    except OSError:
        md = '# 安全与合规声明' + chr(10) + chr(10) + '文档缺失：docs/安全与合规声明.md'
    return render_template('doc_view.html', title='安全与合规声明', body=md_to_html(md))

@app.route('/docs/data-provenance')
@require_login(api=False)
def docs_data_provenance():
    """在浏览器中展示「数据来源说明」文档。

    数据透明度：界面上所有标注为「沙箱模拟 / 模拟值」的数据，
    使用者都能一键查到它的生成方式与真实化路径，而不是只能相信我们的说法。
    """
    root = os.path.dirname(os.path.abspath(__file__))
    md_path = os.path.join(root, 'docs', '数据来源说明.md')
    try:
        with open(md_path, encoding='utf-8') as f:
            md = f.read()
    except OSError:
        md = '# 数据来源说明' + chr(10) + chr(10) + '文档缺失：docs/数据来源说明.md'
    return render_template('doc_view.html', title='数据来源说明', body=md_to_html(md))


def md_to_html(md):
    """极简 Markdown 渲染器（不为一份文档引入额外依赖）。

    仅支持本文档实际用到的语法：标题、粗体、行内代码、表格、有序/无序列表、
    引用块、分隔线、段落。所有文本先做 HTML 转义，避免文档内容造成注入。
    """
    import html as _html
    import re as _re

    def inline(s):
        s = _html.escape(s, quote=False)
        s = _re.sub(r'`([^`]+)`', r'<code>\1</code>', s)
        s = _re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', s)
        return s

    lines = md.split('\n')
    out, i = [], 0
    while i < len(lines):
        ln = lines[i]
        if ln.strip().startswith('|'):
            block = []
            while i < len(lines) and lines[i].strip().startswith('|'):
                block.append(lines[i].strip())
                i += 1
            rows = [[c.strip() for c in r.strip('|').split('|')] for r in block]
            if len(rows) >= 2 and set(rows[1][0]) <= set('-: '):
                head, data = rows[0], rows[2:]
            else:
                head, data = rows[0], rows[1:]
            t = ['<table class="doc-table"><thead><tr>']
            t += ['<th>' + inline(c) + '</th>' for c in head]
            t.append('</tr></thead><tbody>')
            for r in data:
                t.append('<tr>' + ''.join('<td>' + inline(c) + '</td>' for c in r) + '</tr>')
            t.append('</tbody></table>')
            out.append(''.join(t))
            continue
        if ln.startswith('#'):
            lvl = min(len(ln) - len(ln.lstrip('#')), 6)
            out.append('<h' + str(lvl) + '>' + inline(ln.lstrip('#').strip()) + '</h' + str(lvl) + '>')
        elif ln.strip() in ('---', '***'):
            out.append('<hr>')
        elif ln.strip().startswith('>'):
            out.append('<blockquote>' + inline(ln.strip().lstrip('>').strip()) + '</blockquote>')
        elif _re.match(r'^\s*[-*]\s+', ln):
            items = []
            while i < len(lines) and _re.match(r'^\s*[-*]\s+', lines[i]):
                items.append('<li>' + inline(_re.sub(r'^\s*[-*]\s+', '', lines[i])) + '</li>')
                i += 1
            out.append('<ul>' + ''.join(items) + '</ul>')
            continue
        elif _re.match(r'^\s*\d+\.\s+', ln):
            items = []
            while i < len(lines) and _re.match(r'^\s*\d+\.\s+', lines[i]):
                items.append('<li>' + inline(_re.sub(r'^\s*\d+\.\s+', '', lines[i])) + '</li>')
                i += 1
            out.append('<ol>' + ''.join(items) + '</ol>')
            continue
        elif ln.strip():
            out.append('<p>' + inline(ln) + '</p>')
        i += 1
    return '\n'.join(out)

@app.route('/api/ddos/wave')
@require_login()
def api_ddos_wave():
    """获取当前攻击浪潮阶段。

    返回阶段名、剩余时长、已完成浪潮数与当前速率，
    供前端渲染「平静期 / 攀升期 / 突袭期 / 消退期」徽章。
    浪潮结构下平静期画面会明显安静，必须让阶段可见，
    否则使用者会以为系统停止工作了。
    """
    return jsonify(get_wave_status())


# ============================================================================
#                              应用启动入口
# ============================================================================

def open_browser():
    """
    自动打开浏览器访问应用首页

    在独立线程中延迟 1.5 秒执行，确保 Flask 服务器已完全启动
    """
    time.sleep(1.5)
    webbrowser.open_new("http://127.0.0.1:5000/login")


# ============================================================================
#              演示控制接口（默认关闭，DEMO_MODE=1 时启用）
# ============================================================================
# 设计说明：暴力破解演示链（生成日志 → 执行检测 → 查看告警 → 查看黑名单）
# 原先只有 GET 接口且前端无入口，现场只能手敲 URL。
# 这里在 DEMO_MODE=1 时注册对应 POST 接口，并限定请求来自本机；
# 正式部署（演示模式关闭）时不会暴露"一键生成数据/触发检测"能力。
DEMO_MODE = os.environ.get("DEMO_MODE", "0") == "1"


def _is_local_request():
    """仅允许来自本机的演示操作请求。"""
    addr = (request.remote_addr or "").strip()
    return addr in ("127.0.0.1", "::1", "localhost")


if DEMO_MODE:
    @require_role(ROLE_ADMIN)
    @app.route('/api/demo/generate-logs', methods=['POST'])
    def api_demo_generate_logs():
        """生成模拟登录日志（演示用，仅本机可调用）"""
        if not _is_local_request():
            return jsonify({"status": "error", "message": "仅允许本机操作"}), 403
        count = int((request.get_json(silent=True) or {}).get('count', 1000))
        count = max(1, min(count, 5000))
        generate_mock_logs(count)
        return jsonify({"status": "success", "message": f"已生成 {count} 条模拟登录日志"})

    @require_role(ROLE_ADMIN)
    @app.route('/api/demo/run-detection', methods=['POST'])
    def api_demo_run_detection():
        """执行全部暴力破解检测规则（演示用，仅本机可调用）"""
        if not _is_local_request():
            return jsonify({"status": "error", "message": "仅允许本机操作"}), 403
        run_all_detections()
        return jsonify({"status": "success", "message": "5 条检测规则执行完成"})

    @require_role(ROLE_ADMIN)
    @app.route('/api/demo/trigger-wave', methods=['POST'])
    @require_role(ROLE_ADMIN)
    def api_demo_trigger_wave():
        """手动引燃一波攻击（演示用）。

        浪潮结构让"平静期"成为常态（真实 DDoS 本就如此），
        但答辩现场不能干等 2 分钟。该接口把状态机直接推进到突袭期，
        既保留真实的时间结构，又允许演示者主动制造攻击高峰。
        """
        if not _is_local_request():
            return jsonify({"status": "error", "message": "仅允许本机操作"}), 403
        info = trigger_wave(force_surge=True)
        return jsonify({
            "status": "success",
            "message": "已引燃一波攻击（进入{}）".format(info["label"]),
            "wave": info,
        })

    @app.route('/api/demo/reset-ddos', methods=['POST'])
    def api_demo_reset_ddos():
        """重置 DDoS 模拟状态（演示用，仅本机可调用）"""
        if not _is_local_request():
            return jsonify({"status": "error", "message": "仅允许本机操作"}), 403
        return jsonify(reset_state())


if __name__ == '__main__':
    # 再次初始化数据库（确保在 reloader 模式下也能正确创建表）
    init_db()

    # 后台线程打开浏览器（非阻塞）
    threading.Thread(target=open_browser, daemon=True).start()

    # 打印启动横幅
    print("\n" + "=" * 60)
    print("  DDoS 防护监控平台 v2.0 启动中...")
    print("  WebSocket 实时推送已启用")
    print("  DDoS 攻击模拟器已就绪")
    print("  访问: http://127.0.0.1:5000")
    print("=" * 60 + "\n")

    # 启动 DDoS 后台模拟线程
    start_simulator()

    # 启动 Flask-SocketIO 服务器
    # use_reloader=False 避免 debug 模式下的双进程问题
    # 安全加固：debug=False（关闭 Werkzeug 调试器，避免 RCE 入口）；
    # host 收敛为 127.0.0.1（原 0.0.0.0 会在会场网络下暴露给同网段所有人）。
    socketio.run(app, debug=False, host='127.0.0.1', port=5000, use_reloader=False)
