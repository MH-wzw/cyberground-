"""
==============================================================================
  CyberGuard — 认证路由蓝图
==============================================================================
  提供登录、注册、登出三个公开页面，以及一个仅管理员可见的用户管理页。

  与主应用的分工：
  - 本模块负责「页面 + 会话」层面的认证流程
  - jsonify 形态的权限校验（装饰器）在 utils/auth.py 中提供
  - 黑名单拦截与 CSRF 校验在主应用 app.py 的 before_request 中统一处理

  路由清单：
    GET  /login    登录页（已登录则跳转首页）
    POST /login    提交登录
    GET  /register 注册页（注册一律为 viewer 角色）
    POST /register 提交注册
    GET  /logout   登出
    GET  /users    用户管理页（仅 admin）
    GET  /403      无权限提示页
==============================================================================
"""

from flask import (
    Blueprint, render_template, request, redirect, url_for,
    session, flash, jsonify
)

from utils.auth import (
    ROLE_ADMIN, ROLE_VIEWER, ROLE_LABELS,
    create_user, verify_user, get_all_users, update_user, delete_user,
    count_admins, current_user, is_admin, login_session, logout_session,
    issue_csrf_token, update_user as _update_user,
)

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """登录页。GET 渲染表单，POST 校验凭证并写入会话。"""
    if current_user():
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ok, user, msg = verify_user(username, password)
        if ok:
            login_session(user)
            nxt = request.args.get("next") or request.form.get("next") or "/"
            # 只允许站内相对跳转，避免开放重定向
            if not nxt.startswith("/") or nxt.startswith("//"):
                nxt = "/"
            return redirect(nxt)
        flash(msg, "error")

    return render_template("login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """注册页。

    注意：注册通路**只创建 viewer（只读）角色**。
    管理员角色无法自助注册获得，只能由既有管理员在用户管理页授予。
    """
    if current_user():
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if password != confirm:
            flash("两次输入的密码不一致", "error")
        else:
            # 安全边界：自助注册一律强制只读角色，不接受任何外部指定的角色
            ok, msg = create_user(username, password, force_viewer=True)
            if ok:
                flash("注册成功，请使用新账号登录", "success")
                return redirect(url_for("auth.login"))
            flash(msg, "error")

    return render_template("register.html")


@auth_bp.route("/logout")
def logout():
    """登出并回到登录页。"""
    logout_session()
    return redirect(url_for("auth.login"))


@auth_bp.route("/403")
def forbidden():
    return render_template("403.html"), 403


@auth_bp.route("/users")
def users_page():
    """用户管理页（仅管理员）。普通用户访问会被重定向到 403。"""
    if not current_user():
        return redirect(url_for("auth.login", next=request.path))
    if not is_admin():
        return render_template("403.html"), 403
    return render_template("users.html")


# ============================================================================
#                          用户管理 API（仅管理员）
# ============================================================================

def _admin_guard():
    """返回 None 表示放行，否则返回错误响应。

    权限判断在服务端完成——前端隐藏入口只是体验优化，不是安全边界。
    """
    if not current_user():
        return jsonify({"status": "error", "message": "请先登录"}), 401
    if not is_admin():
        return jsonify({"status": "error", "message": "权限不足：该操作仅限管理员"}), 403
    return None


@auth_bp.route("/api/users")
def api_users():
    """用户列表（仅管理员）。"""
    guard = _admin_guard()
    if guard:
        return guard
    return jsonify(get_all_users())


@auth_bp.route("/api/users/update/<int:user_id>", methods=["POST"])
def api_users_update(user_id):
    """修改用户的角色 / 状态 / 密码（仅管理员）。"""
    guard = _admin_guard()
    if guard:
        return guard

    data = request.get_json(silent=True) or {}
    me = current_user()
    target = None
    for u in get_all_users():
        if u[0] == user_id:
            target = u
            break
    if not target:
        return jsonify({"status": "error", "message": "用户不存在"}), 404

    new_role = data.get("role")
    new_status = data.get("status")
    password = data.get("password") or None

    # 保护措施 1：不能把自己降级或禁用，避免管理员一键把自己锁在门外
    if user_id == me["id"]:
        if new_role and new_role != ROLE_ADMIN:
            return jsonify({"status": "error", "message": "不能修改自己的角色"}), 400
        if new_status and new_status != "active":
            return jsonify({"status": "error", "message": "不能禁用自己的账户"}), 400

    # 保护措施 2：不能移除最后一个可用管理员
    if (new_role and new_role != ROLE_ADMIN) or (new_status and new_status != "active"):
        if target[2] == ROLE_ADMIN and count_admins(exclude_id=user_id) == 0:
            return jsonify({"status": "error", "message": "系统必须保留至少一个管理员"}), 400

    ok, msg = update_user(user_id, role=new_role, status=new_status, password=password)
    return jsonify({"status": "success" if ok else "error", "message": msg}), (200 if ok else 400)


@auth_bp.route("/api/users/delete/<int:user_id>", methods=["POST"])
def api_users_delete(user_id):
    """删除用户（仅管理员）。"""
    guard = _admin_guard()
    if guard:
        return guard

    me = current_user()
    if user_id == me["id"]:
        return jsonify({"status": "error", "message": "不能删除自己的账户"}), 400

    target = None
    for u in get_all_users():
        if u[0] == user_id:
            target = u
            break
    if not target:
        return jsonify({"status": "error", "message": "用户不存在"}), 404

    if target[2] == ROLE_ADMIN and count_admins(exclude_id=user_id) == 0:
        return jsonify({"status": "error", "message": "系统必须保留至少一个管理员"}), 400

    ok = delete_user(user_id)
    return jsonify({"status": "success" if ok else "error",
                    "message": "已删除" if ok else "删除失败"}), (200 if ok else 400)


@auth_bp.route("/api/me")
def api_me():
    """返回当前登录用户与权限集合，供前端做界面降级渲染。"""
    u = current_user()
    if not u:
        return jsonify({"status": "anonymous"}), 401
    from utils.auth import ROLE_PERMISSIONS
    return jsonify({
        "status": "ok",
        "user": u,
        "role_label": ROLE_LABELS.get(u["role"], u["role"]),
        "permissions": ROLE_PERMISSIONS.get(u["role"], ROLE_PERMISSIONS[ROLE_VIEWER]),
        "csrf_token": issue_csrf_token(),
    })
