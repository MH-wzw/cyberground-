# -*- coding: utf-8 -*-
"""CyberGuard 鉴权与权限矩阵验证脚本。

用法： python _auth_verify.py

设计要点：
  Flask 的 test_client 会保留会话 Cookie，因此"匿名"场景必须使用全新客户端，
  否则会带着管理员会话去测匿名，得到假阳性结果。本脚本为每个场景单独建客户端，
  并用 _logout 显式确认会话状态。
"""
import os
import sys
import json

# 项目根目录（不是 tests/ 目录）。
# 原先写成 __file__ 的 dirname 即 tests/，导致 os.chdir 到 tests/ 后
# config.DATABASE_PATH 的相对路径 "db.sqlite3" 解析成 tests/db.sqlite3 ——
# 于是每跑一次这个脚本就在 tests/ 下留下一个数据库副本，
# 而且校验的是空库，不是真实数据。
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)
os.environ.setdefault("DEMO_MODE", "1")

import app as A  # noqa: E402
from utils.auth import create_user, delete_user, get_all_users  # noqa: E402
from utils.db_helper import add_to_blacklist, remove_from_blacklist  # noqa: E402

ADMIN = ("admin", "Admin@123")
VIEWER_NAME = "__verify_viewer__"
VIEWER_PASS = "Viewer@123"

results = []


def check(name, cond, detail=""):
    results.append((bool(cond), name, detail))
    print(f"  {'OK  ' if cond else 'FAIL'}  {name}" + (f"   {detail}" if detail else ""))


def fresh():
    """全新客户端（无任何会话 Cookie）——真正的匿名身份。"""
    return A.app.test_client()


def login(user, pwd):
    c = A.app.test_client()
    r = c.post("/login", data={"username": user, "password": pwd}, follow_redirects=False)
    return c, r


def csrf_of(c):
    return (c.get("/api/me").get_json() or {}).get("csrf_token", "")


def post(c, url, payload):
    return c.post(url, json=payload, headers={"X-CSRF-Token": csrf_of(c)})


PAGES = ["/", "/logs", "/alerts", "/blacklist", "/heatmap", "/attack-chain", "/users"]
QUERY_APIS = ["/api/logs", "/api/alerts", "/api/blacklist", "/api/stats",
              "/api/ddos/state", "/api/ddos/geo", "/api/ddos/timeline"]

print("=" * 70)
print(" 1) 匿名访问：页面应 302 跳登录页；查询接口应 401")
print("=" * 70)
anon = fresh()
for p in PAGES:
    r = anon.get(p, follow_redirects=False)
    loc = r.headers.get("Location", "")
    check(f"匿名 {p:<14}", r.status_code == 302 and "auth" not in loc and "login" in loc,
          f"{r.status_code} -> {loc}")
for p in QUERY_APIS + ["/api/users", "/api/me"]:
    check(f"匿名 {p:<20}", anon.get(p).status_code == 401)

print()
print("=" * 70)
print(" 2) 匿名可访问登录/注册页")
print("=" * 70)
for p in ["/login", "/register"]:
    r = anon.get(p)
    check(f"匿名 {p}", r.status_code == 200, f"{r.status_code}, {len(r.data)}B")

print()
print("=" * 70)
print(" 3) 管理员登录与全量访问")
print("=" * 70)
adm, r = login(*ADMIN)
check("admin 登录", r.status_code == 302, f"{r.status_code} -> {r.headers.get('Location','')}")
me = adm.get("/api/me").get_json() or {}
check("取得身份", me.get("status") == "ok", json.dumps(me, ensure_ascii=False)[:120])
check("角色为管理员", me.get("user", {}).get("role") == "admin")
for p in PAGES:
    r = adm.get(p)
    check(f"admin {p:<14}", r.status_code == 200, f"{r.status_code}, {len(r.data)}B")
for p in QUERY_APIS:
    check(f"admin {p:<20}", adm.get(p).status_code == 200)

print()
print("=" * 70)
print(" 4) 管理员写操作")
print("=" * 70)
r = post(adm, "/api/blacklist/add", {"ip": "203.0.113.254", "reason": "__verify__", "hours": 1})
check("admin 加黑名单", r.status_code == 200, f"{r.status_code} {r.get_json()}")
bl = adm.get("/api/blacklist").get_json() or []
row = [b for b in bl if b[1] == "203.0.113.254"]
if row:
    r = post(adm, f"/api/blacklist/remove/{row[0][0]}", {})
    check("admin 解封", r.status_code == 200, f"{r.status_code}")

print()
print("=" * 70)
print(" 5) 自助注册强制只读（防自提权）")
print("=" * 70)
reg = fresh()
r = reg.post("/register", data={"username": VIEWER_NAME, "password": VIEWER_PASS,
                                "confirm": VIEWER_PASS}, follow_redirects=False)
check("注册成功", r.status_code == 302, f"{r.status_code} -> {r.headers.get('Location','')}")
users = get_all_users()
u = [x for x in users if x[1] == VIEWER_NAME]
check("用户已创建", bool(u))
if u:
    check("注册所得角色为 viewer（非管理员）", u[0][2] == "viewer", f"role={u[0][2]}")
# 即使伪造 role 字段提交，也必须仍是 viewer
reg2 = fresh()
reg2.post("/register", data={"username": "__verify_evil__", "password": VIEWER_PASS,
                             "confirm": VIEWER_PASS, "role": "admin"}, follow_redirects=False)
ev = [x for x in get_all_users() if x[1] == "__verify_evil__"]
if ev:
    check("伪造 role=admin 仍为 viewer", ev[0][2] == "viewer", f"role={ev[0][2]}")
else:
    check("伪造 role=admin 仍为 viewer", False, "用户未创建")
# 直接调用底层函数要求 force_viewer 才安全
ok, msg = create_user("__verify_admin_try__", VIEWER_PASS, role="admin", force_viewer=True)
at = [x for x in get_all_users() if x[1] == "__verify_admin_try__"]
if at:
    check("force_viewer=True 时 role 被强制降级", at[0][2] == "viewer", f"role={at[0][2]}")
else:
    check("force_viewer=True 时 role 被强制降级", False, msg)

print()
print("=" * 70)
print(" 6) 普通用户（只读）权限矩阵")
print("=" * 70)
vw, r = login(VIEWER_NAME, VIEWER_PASS)
check("viewer 登录", r.status_code == 302, f"{r.status_code}")
vme = vw.get("/api/me").get_json() or {}
check("viewer 角色正确", vme.get("user", {}).get("role") == "viewer")
perms = vme.get("permissions", {})
check("权限集合全为只读", not any(perms.values()), json.dumps(perms, ensure_ascii=False))

print("  --- 可查看 ---")
for p in PAGES:
    r = vw.get(p, follow_redirects=False)
    if p == "/users":
        check(f"viewer {p} 被拒", r.status_code == 403, f"{r.status_code}")
    else:
        check(f"viewer {p:<14}", r.status_code == 200, f"{r.status_code}, {len(r.data)}B")
for p in QUERY_APIS:
    check(f"viewer {p:<20}", vw.get(p).status_code == 200)

print("  --- 写操作必须被服务端拒绝 ---")
# 说明：请求会依次经过 before_request（CSRF 校验）→ 视图守卫（角色校验）。
# 因此同时缺令牌又越权时，最先触发的是 CSRF 的 400。这里分两种情形分别断言，
# 避免把"被 CSRF 拦下"误判为"权限没生效"。
r = vw.post("/api/blacklist/add", json={"ip": "203.0.113.253", "reason": "x", "hours": 1})
check("viewer 无令牌写 -> 被拒(400/403)", r.status_code in (400, 403), f"{r.status_code}")
r = vw.post("/api/blacklist/add", json={"ip": "203.0.113.253", "reason": "x", "hours": 1},
            headers={"X-CSRF-Token": csrf_of(vw)})
check("viewer 带令牌加黑名单 -> 403", r.status_code == 403,
      f"{r.status_code} {(r.get_json() or {}).get('message', '')}")
r = vw.post("/api/alerts/update/1", json={"status": "已处理"}, headers={"X-CSRF-Token": csrf_of(vw)})
check("viewer 带令牌改告警 -> 403", r.status_code == 403, f"{r.status_code}")
r = vw.post("/api/users/update/1", json={"role": "admin"}, headers={"X-CSRF-Token": csrf_of(vw)})
check("viewer 带令牌改用户 -> 403", r.status_code == 403, f"{r.status_code}")
r = vw.post("/api/users/delete/1", json={}, headers={"X-CSRF-Token": csrf_of(vw)})
check("viewer 带令牌删用户 -> 403", r.status_code == 403, f"{r.status_code}")
# 这三个接口会写库，已限定为 POST（避免 CSRF 通过 GET 触发）。
# 这里必须用 POST + 有效 CSRF 令牌，才能确认「是权限拦住了 viewer」，
# 而不是「方法不对被 405 挡掉」。
_H = {"X-CSRF-Token": csrf_of(vw)}
check("viewer 执行检测 -> 403", vw.post("/api/run_detection", json={}, headers=_H).status_code == 403)
check("viewer 生成日志 -> 403", vw.post("/api/generate_logs", json={}, headers=_H).status_code == 403)
check("viewer 重置模拟 -> 403", vw.post("/api/ddos/reset", json={}, headers=_H).status_code == 403)
check("viewer 查用户表 -> 403", vw.get("/api/users").status_code == 403)

print()
print("=" * 70)
print(" 7) CSRF 保护")
print("=" * 70)
raw, _ = login(*ADMIN)
r = raw.post("/api/blacklist/add", json={"ip": "203.0.113.252", "reason": "csrf", "hours": 1})
check("无令牌写请求被拒 -> 400", r.status_code == 400, f"{r.status_code}")
tok = csrf_of(raw)
r = raw.post("/api/blacklist/add", json={"ip": "203.0.113.252", "reason": "__verify__", "hours": 1},
             headers={"X-CSRF-Token": tok})
check("携带正确令牌通过 -> 200", r.status_code == 200, f"{r.status_code}")
r = raw.post("/api/blacklist/add", json={"ip": "203.0.113.251", "reason": "x", "hours": 1},
             headers={"X-CSRF-Token": "wrong-token-value"})
check("错误令牌被拒 -> 400", r.status_code == 400, f"{r.status_code}")
for b in (raw.get("/api/blacklist").get_json() or []):
    if b[1] in ("203.0.113.252", "203.0.113.251"):
        post(raw, f"/api/blacklist/remove/{b[0]}", {})

print()
print("=" * 70)
print(" 8) 黑名单真实拦截")
print("=" * 70)
blocked_ip = "198.51.100.77"
add_to_blacklist(blocked_ip, "__verify_block__", block_hours=1)
atk = fresh()
r = atk.get("/api/stats", environ_base={"REMOTE_ADDR": blocked_ip})
check("被封禁 IP 的 API 请求 -> 403", r.status_code == 403, f"{r.status_code} {(r.get_json() or {}).get('status')}")
r = atk.get("/", environ_base={"REMOTE_ADDR": blocked_ip})
check("被封禁 IP 的页面请求 -> 拦截页", r.status_code == 403 and "BLOCKED" in r.get_data(as_text=True), f"{r.status_code}")
r = atk.get("/login", environ_base={"REMOTE_ADDR": blocked_ip})
check("被封禁 IP 连登录页也被拦", r.status_code == 403, f"{r.status_code}")
r = atk.get("/login", environ_base={"REMOTE_ADDR": "127.0.0.1"})
check("本机回环地址不被拦截（自救通路）", r.status_code == 200, f"{r.status_code}")
add_to_blacklist("198.51.100.78", "__verify_expired__", block_hours=-1)
r = atk.get("/login", environ_base={"REMOTE_ADDR": "198.51.100.78"})
check("已过期封禁不再拦截", r.status_code == 200, f"{r.status_code}")
remove_from_blacklist(blocked_ip)
remove_from_blacklist("198.51.100.78")

print()
print("=" * 70)
print(" 9) 管理员自我保护约束")
print("=" * 70)
admin_id = [x for x in get_all_users() if x[1] == "admin"][0][0]
r = post(adm, f"/api/users/update/{admin_id}", {"role": "viewer"})
check("不能把自己降级", r.status_code == 400, f"{r.status_code} {(r.get_json() or {}).get('message')}")
r = post(adm, f"/api/users/update/{admin_id}", {"status": "disabled"})
check("不能禁用自己的账户", r.status_code == 400, f"{r.status_code}")
r = post(adm, f"/api/users/delete/{admin_id}", {})
check("不能删除自己的账户", r.status_code == 400, f"{r.status_code}")
# 管理员改他人角色应当成功
vid = [x for x in get_all_users() if x[1] == VIEWER_NAME][0][0]
r = post(adm, f"/api/users/update/{vid}", {"role": "admin"})
check("管理员可把他人提升为管理员", r.status_code == 200, f"{r.status_code}")
r = post(adm, f"/api/users/update/{vid}", {"role": "viewer"})
check("管理员可把他人降回只读", r.status_code == 200, f"{r.status_code}")

print()
print("=" * 70)
print(" 10) 清理测试数据")
print("=" * 70)
for name in (VIEWER_NAME, "__verify_admin_try__", "__verify_evil__"):
    for x in get_all_users():
        if x[1] == name:
            delete_user(x[0])
            print(f"  已删除测试用户 {name}")
print(f"  当前黑名单：{len(adm.get('/api/blacklist').get_json() or [])} 条")
print(f"  当前用户数：{len(get_all_users())}")

print()
total = len(results)
passed = sum(1 for ok, _, _ in results if ok)
print("=" * 70)
print(f" 结果：{passed}/{total} 通过")
if passed < total:
    print(" 未通过项：")
    for ok, name, detail in results:
        if not ok:
            print(f"   - {name}  {detail}")
print("=" * 70)
sys.exit(0 if passed == total else 1)
