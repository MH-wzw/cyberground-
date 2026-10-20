"""
==============================================================================
  CyberGuard — 认证与权限模块
==============================================================================
  本模块提供基于 Flask Session 的登录认证与两级角色授权（RBAC）：

  角色模型（两级）：
  ┌──────────┬──────────────────────────────────────────────────────────┐
  │ admin    │ 管理员：可执行全部写操作                                   │
  │          │   黑名单增删、告警状态更新、生成日志、执行检测、             │
  │          │   用户管理（禁用/启用、改角色、重置密码、删除）             │
  ├──────────┼──────────────────────────────────────────────────────────┤
  │ viewer   │ 普通用户：只读。所有页面与查询接口可访问，                    │
  │          │   但任何写操作在**后端被 403 拒绝**（前端同时隐藏按钮）      │
  └──────────┴──────────────────────────────────────────────────────────┘

  安全设计要点：
  1. 密码使用 werkzeug.security 的 PBKDF2-SHA256 加盐哈希，绝不存明文
  2. 会话密钥从环境变量读取，未配置时生成随机值（重启即失效，避免硬编码）
  3. 写操作统一经 require_role('admin') 装饰器校验，权限判断在**服务端**完成，
     前端隐藏按钮只是体验优化，不作为安全边界
  4. 提供 CSRF 令牌校验（登记型），配合 before_request 校验写请求
  5. 注册只允许创建 viewer 角色，管理员角色只能由既有管理员授予

  数据表：users
  ┌─ id, username(UNIQUE), password_hash, role, status,
  │  created_at, last_login_at, login_count
  └─
==============================================================================
"""

import datetime
import functools
import secrets

from flask import session, jsonify, redirect, request, url_for
from werkzeug.security import generate_password_hash, check_password_hash

from utils.db_helper import _get_conn

# ============================ 角色定义 ============================
ROLE_ADMIN = "admin"      # 管理员：可写
ROLE_VIEWER = "viewer"    # 普通用户：只读

ROLE_LABELS = {
    ROLE_ADMIN: "管理员",
    ROLE_VIEWER: "普通用户",
}

# 各角色可执行的操作（用于前端渲染与文档说明，后端仍以装饰器为准）
ROLE_PERMISSIONS = {
    ROLE_ADMIN: {
        "blacklist_write": True, "alert_write": True,
        "run_detection": True, "generate_logs": True, "user_manage": True,
    },
    ROLE_VIEWER: {
        "blacklist_write": False, "alert_write": False,
        "run_detection": False, "generate_logs": False, "user_manage": False,
    },
}

# 密码策略
MIN_PASSWORD_LENGTH = 6
MAX_USERNAME_LENGTH = 32


# ============================================================================
#                              建表与初始化
# ============================================================================

def init_auth_db():
    """创建 users 表（幂等），并确保存在一个默认管理员账户。

    默认管理员仅用于首次登录演示，首次登录后应尽快改密。
    账户名与初始密码可通过环境变量覆盖：
        CYBERGUARD_ADMIN_USER / CYBERGUARD_ADMIN_PASS
    """
    import os

    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'viewer',
                status        TEXT NOT NULL DEFAULT 'active',
                created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login_at DATETIME,
                login_count   INTEGER DEFAULT 0
            )
        ''')
        conn.commit()

        # 首次运行时创建默认管理员
        cur.execute("SELECT COUNT(*) FROM users WHERE role = ?", (ROLE_ADMIN,))
        if cur.fetchone()[0] == 0:
            admin_user = os.environ.get("CYBERGUARD_ADMIN_USER", "admin")
            admin_pass = os.environ.get("CYBERGUARD_ADMIN_PASS", "Admin@123")
            cur.execute(
                'INSERT OR IGNORE INTO users (username, password_hash, role, status) '
                'VALUES (?, ?, ?, ?)',
                (admin_user, generate_password_hash(admin_pass), ROLE_ADMIN, "active")
            )
            conn.commit()
            print(f"✅ 已创建默认管理员账户：{admin_user} / {admin_pass}（请尽快修改密码）")
    finally:
        conn.close()


# ============================================================================
#                              用户 CRUD
# ============================================================================

def create_user(username, password, role=ROLE_VIEWER, force_viewer=False):
    """创建用户。

    Args:
        role:          期望角色（仅管理员调用通路可指定非 viewer）
        force_viewer:  强制创建为只读角色。自助注册通路必须传 True，
                       从调用层面杜绝"注册即管理员"的自提权风险。

    Returns:
        (ok: bool, message: str)
    """
    username = (username or "").strip()
    if not username:
        return False, "用户名不能为空"
    if len(username) > MAX_USERNAME_LENGTH:
        return False, f"用户名长度不能超过 {MAX_USERNAME_LENGTH} 个字符"
    if not username.replace("_", "").replace("-", "").isalnum():
        return False, "用户名只能包含字母、数字、下划线和连字符"
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return False, f"密码长度至少 {MIN_PASSWORD_LENGTH} 位"

    # 安全边界：自助注册通路不得创建管理员
    if force_viewer:
        role = ROLE_VIEWER
    if role not in (ROLE_ADMIN, ROLE_VIEWER):
        role = ROLE_VIEWER

    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cur.fetchone():
            return False, "该用户名已被注册"
        cur.execute(
            'INSERT INTO users (username, password_hash, role, status) VALUES (?, ?, ?, ?)',
            (username, generate_password_hash(password), role, "active")
        )
        conn.commit()
        return True, "注册成功"
    except Exception as e:
        return False, f"注册失败：{e}"
    finally:
        conn.close()


def verify_user(username, password):
    """校验账号密码。

    Returns:
        (ok: bool, user: dict|None, message: str)
    """
    username = (username or "").strip()
    if not username or not password:
        return False, None, "请输入用户名和密码"

    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, password_hash, role, status FROM users WHERE username = ?",
            (username,)
        )
        row = cur.fetchone()
        if not row:
            return False, None, "用户名或密码错误"
        user = {"id": row[0], "username": row[1], "role": row[3], "status": row[4]}
        if user["status"] != "active":
            return False, None, "该账户已被禁用，请联系管理员"
        if not check_password_hash(row[2], password):
            return False, None, "用户名或密码错误"
        # 记录登录
        cur.execute(
            "UPDATE users SET last_login_at = ?, login_count = COALESCE(login_count, 0) + 1 "
            "WHERE id = ?",
            (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user["id"])
        )
        conn.commit()
        return True, user, "登录成功"
    finally:
        conn.close()


def get_all_users():
    """返回全部用户（不含密码哈希），供管理员页面展示。"""
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, role, status, created_at, last_login_at, "
            "COALESCE(login_count, 0) FROM users ORDER BY id ASC"
        )
        return [tuple(r) for r in cur.fetchall()]
    finally:
        conn.close()


def get_user_by_id(user_id):
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, username, role, status FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        return {"id": row[0], "username": row[1], "role": row[2], "status": row[3]} if row else None
    finally:
        conn.close()


def update_user(user_id, role=None, status=None, password=None):
    """管理员更新用户角色/状态/密码。"""
    sets, params = [], []
    if role in (ROLE_ADMIN, ROLE_VIEWER):
        sets.append("role = ?"); params.append(role)
    if status in ("active", "disabled"):
        sets.append("status = ?"); params.append(status)
    if password:
        if len(password) < MIN_PASSWORD_LENGTH:
            return False, f"密码长度至少 {MIN_PASSWORD_LENGTH} 位"
        sets.append("password_hash = ?"); params.append(generate_password_hash(password))
    if not sets:
        return False, "没有需要更新的字段"

    conn = _get_conn()
    try:
        cur = conn.cursor()
        params.append(user_id)
        cur.execute(f"UPDATE users SET {', '.join(sets)} WHERE id = ?", params)
        conn.commit()
        return (cur.rowcount > 0), ("更新成功" if cur.rowcount > 0 else "用户不存在")
    finally:
        conn.close()


def delete_user(user_id):
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def count_admins(exclude_id=None):
    """统计启用状态的管理员数量（用于防止删掉最后一个管理员）。"""
    conn = _get_conn()
    try:
        cur = conn.cursor()
        sql = "SELECT COUNT(*) FROM users WHERE role = ? AND status = 'active'"
        params = [ROLE_ADMIN]
        if exclude_id is not None:
            sql += " AND id != ?"; params.append(exclude_id)
        cur.execute(sql, params)
        return cur.fetchone()[0]
    finally:
        conn.close()


# ============================================================================
#                          会话与权限装饰器
# ============================================================================

def current_user():
    """返回当前登录用户（未登录返回 None）。"""
    uid = session.get("uid")
    if not uid:
        return None
    return {
        "id": uid,
        "username": session.get("username"),
        "role": session.get("role", ROLE_VIEWER),
    }


def is_admin():
    u = current_user()
    return bool(u and u["role"] == ROLE_ADMIN)


def login_session(user):
    """写入登录会话。"""
    session.clear()
    session["uid"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session["csrf_token"] = secrets.token_urlsafe(32)
    session.permanent = False


def logout_session():
    session.clear()


def issue_csrf_token():
    """获取（必要时生成）当前会话的 CSRF 令牌。"""
    tok = session.get("csrf_token")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
    return tok


def csrf_ok():
    """校验写请求携带的 CSRF 令牌。"""
    expected = session.get("csrf_token")
    if not expected:
        return False
    got = request.headers.get("X-CSRF-Token") or (request.get_json(silent=True) or {}).get("_csrf")
    return bool(got) and secrets.compare_digest(str(got), str(expected))


def require_login(*, api=True):
    """要求已登录。api=True 时返回 401 JSON，否则重定向到登录页。

    注意：认证路由注册在 auth 蓝图下，端点名必须是 'auth.login'
    （写成 'login' 会抛 BuildError，表现为 500）。
    """
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            if current_user():
                return fn(*a, **kw)
            if api:
                return jsonify({"status": "error", "message": "请先登录"}), 401
            return redirect(url_for("auth.login", next=request.path))
        return wrapper
    return deco


def require_role(role, *, api=True):
    """要求具备指定角色。未登录 → 401/跳登录；已登录但权限不足 → 403。

    权限判断在服务端完成：前端隐藏按钮只是体验优化，不构成安全边界。
    """
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            user = current_user()
            if not user:
                if api:
                    return jsonify({"status": "error", "message": "请先登录"}), 401
                return redirect(url_for("auth.login", next=request.path))
            if user["role"] != role and user["role"] != ROLE_ADMIN:
                if api:
                    return jsonify({
                        "status": "error",
                        "message": "权限不足：该操作仅限管理员",
                    }), 403
                return render_forbidden(), 403
            return fn(*a, **kw)
        return wrapper
    return deco


def render_forbidden():
    from flask import render_template
    return render_template("403.html")
