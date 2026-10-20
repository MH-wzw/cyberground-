"""
==============================================================================
  CyberGuard — 告警通知路由
==============================================================================
  提供通知配置页面与相关 API。**全部仅管理员可访问**（服务端强制校验）。

  路由清单：
    GET  /notify                     通知配置页（仅管理员）
    GET  /api/notify/overview        配置 + 规则 + 统计（敏感项掩码）
    POST /api/notify/smtp            保存 SMTP 配置
    POST /api/notify/rules           保存通知规则
    GET  /api/notify/recipients      收件人列表
    POST /api/notify/recipients      新增收件人
    POST /api/notify/recipients/update/<id>   修改收件人
    POST /api/notify/recipients/delete/<id>   删除收件人
    POST /api/notify/test            发送测试邮件（验证配置是否真的可用）
    GET  /api/notify/logs            投递记录
    GET  /api/notify/stats           投递统计

  权限设计说明：
  通知配置包含 SMTP 凭据与收件人邮箱，属于敏感配置；
  且"能改收件人"意味着"能把告警外发到任意邮箱"，
  因此这一组接口必须是管理员专属，而不是登录即可访问。
==============================================================================
"""

from flask import Blueprint, render_template, redirect, url_for, jsonify, request

from utils.auth import current_user, is_admin
from utils import notifier

notify_bp = Blueprint("notify", __name__)


def _admin_guard():
    """返回 None 表示放行，否则返回错误响应。

    权限判断在服务端完成 —— 前端隐藏入口只是体验优化，不构成安全边界。
    """
    if not current_user():
        return jsonify({"status": "error", "message": "请先登录"}), 401
    if not is_admin():
        return jsonify({"status": "error", "message": "权限不足：通知配置仅限管理员"}), 403
    return None


@notify_bp.route("/notify")
def notify_page():
    """通知配置页（仅管理员）。"""
    if not current_user():
        return redirect(url_for("auth.login", next=request.path))
    if not is_admin():
        return render_template("403.html"), 403
    return render_template("notify.html")


@notify_bp.route("/api/notify/overview")
def api_overview():
    """一次性返回页面所需的全部数据（减少往返）。"""
    guard = _admin_guard()
    if guard:
        return guard
    return jsonify({
        "smtp": notifier.smtp_config(mask=True),
        "rules": notifier.rules_config(),
        "recipients": notifier.list_recipients(),
        "stats": notifier.stats(),
        "env_keys": {
            "host": "CYBERGUARD_SMTP_HOST",
            "port": "CYBERGUARD_SMTP_PORT",
            "user": "CYBERGUARD_SMTP_USER",
            "password": "CYBERGUARD_SMTP_PASS",
            "sender": "CYBERGUARD_SMTP_FROM",
        },
    })


@notify_bp.route("/api/notify/smtp", methods=["POST"])
def api_save_smtp():
    guard = _admin_guard()
    if guard:
        return guard
    notifier.save_smtp_config(request.get_json(silent=True) or {})
    return jsonify({"status": "success", "message": "SMTP 配置已保存"})


@notify_bp.route("/api/notify/rules", methods=["POST"])
def api_save_rules():
    guard = _admin_guard()
    if guard:
        return guard
    notifier.save_rules_config(request.get_json(silent=True) or {})
    return jsonify({"status": "success", "message": "通知规则已保存"})


@notify_bp.route("/api/notify/recipients")
def api_recipients():
    guard = _admin_guard()
    if guard:
        return guard
    return jsonify(notifier.list_recipients())


@notify_bp.route("/api/notify/recipients", methods=["POST"])
def api_add_recipient():
    guard = _admin_guard()
    if guard:
        return guard
    data = request.get_json(silent=True) or {}
    ok, msg = notifier.add_recipient(
        data.get("email", ""), data.get("name", ""), data.get("min_risk", "高危"))
    return jsonify({"status": "success" if ok else "error", "message": msg}), (200 if ok else 400)


@notify_bp.route("/api/notify/recipients/update/<int:rid>", methods=["POST"])
def api_update_recipient(rid):
    guard = _admin_guard()
    if guard:
        return guard
    data = request.get_json(silent=True) or {}
    ok, msg = notifier.update_recipient(
        rid,
        name=data.get("name"),
        min_risk=data.get("min_risk"),
        enabled=data.get("enabled"),
    )
    return jsonify({"status": "success" if ok else "error", "message": msg}), (200 if ok else 400)


@notify_bp.route("/api/notify/recipients/delete/<int:rid>", methods=["POST"])
def api_delete_recipient(rid):
    guard = _admin_guard()
    if guard:
        return guard
    ok = notifier.delete_recipient(rid)
    return jsonify({"status": "success" if ok else "error",
                    "message": "已删除" if ok else "收件人不存在"}), (200 if ok else 400)


@notify_bp.route("/api/notify/test", methods=["POST"])
def api_test_send():
    """发送测试邮件。

    这个接口是整套通知功能"可验证性"的关键：
    它让「配置是否真的可用」从一个主观判断变成一次一键可验证的动作 ——
    点一下，邮件要么真的到了，要么明确告诉你失败原因。
    """
    guard = _admin_guard()
    if guard:
        return guard

    recips = [r["email"] for r in notifier.list_recipients(only_enabled=True)]
    demo_alert = [{
        "id": None,
        "alert_time": __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "alert_type": "测试通知",
        "risk_level": "高危",
        "source_ip": "127.0.0.1",
        "description": ("这是一封来自 CyberGuard 的测试邮件，用于验证 SMTP 配置是否正确。"
                        "收到它说明通知链路已打通；真实告警将按设定的规则与聚合策略推送。"),
    }]
    ok, detail, latency = notifier.send_email(demo_alert, purpose="test")
    notifier.log_delivery(demo_alert[0], notifier.ST_SENT if ok else notifier.ST_FAILED,
                          detail=detail, recipient=", ".join(recips),
                          latency_ms=latency)
    return jsonify({
        "status": "success" if ok else "error",
        "message": ("测试邮件已发出（{} ms）".format(latency)) if ok else detail,
        "detail": detail,
        "recipients": recips,
        "latency_ms": latency,
    }), (200 if ok else 400)


@notify_bp.route("/api/notify/logs")
def api_logs():
    guard = _admin_guard()
    if guard:
        return guard
    try:
        limit = max(1, min(int(request.args.get("limit", 100)), 500))
    except ValueError:
        limit = 100
    try:
        offset = max(0, int(request.args.get("offset", 0)))
    except ValueError:
        offset = 0
    return jsonify(notifier.list_logs(limit=limit, offset=offset))


@notify_bp.route("/api/notify/stats")
def api_stats():
    guard = _admin_guard()
    if guard:
        return guard
    return jsonify(notifier.stats())
