"""
==============================================================================
  CyberGuard — 主机资源真实采集模块
==============================================================================
  本模块使用 psutil 读取**操作系统真实计数器**，替代此前按模拟负载派生的
  展示值（原实现为 "系统负载 = 30 + 沙箱带宽/20"，属于编造数字）。

  与 ddos_simulator 的职责边界（重要）：
  ┌────────────────────┬──────────────────────────────────────────────┐
  │ utils/host_metrics │ 真实主机采集：CPU / 内存 / 磁盘 IO / 网卡吞吐  │
  │                    │ 数据来自操作系统，非模拟                      │
  ├────────────────────┼──────────────────────────────────────────────┤
  │ utils/ddos_simulator │ 攻击沙箱：攻击事件 / 流量 / 地理态势         │
  │                    │ 全部为内存模拟，不产生真实网络报文            │
  └────────────────────┴──────────────────────────────────────────────┘
  两者必须保持独立，否则又会混淆"真实"与"模拟"的边界。

  psutil 使用的四个关键点（都是容易踩的坑）：
  1. cpu_percent(interval=None) 是**非阻塞**的相对采样，返回"距上次调用以来"
     的平均占用率；首次调用结果无意义（恒为 0.0），必须丢弃。
     绝不能传 interval=0.1 —— 那会阻塞 100ms，打乱 1.5 秒的实时推送节奏。
  2. disk_io_counters() / net_io_counters() 返回的是**开机以来的累计字节数**，
     必须保存上次采样值、计算差值、再除以**实测**时间间隔得到速率。
     不能假设间隔恒为 1.5 秒（eventlet 调度有抖动）。
  3. 原始读数抖动明显，直接上屏会闪烁。这里用中位数窗口（比均值更抗尖峰）。
  4. 任何一次 psutil 调用都可能失败（权限、平台差异、容器限制），
     必须逐项 try/except 并标记为不可用，绝不能让采样异常中断主循环。
==============================================================================
"""

import time
import threading
import logging
from collections import deque

logger = logging.getLogger(__name__)

try:
    import psutil
    PSUTIL_AVAILABLE = True
    PSUTIL_ERROR = ""
except ImportError as e:                      # pragma: no cover
    psutil = None
    PSUTIL_AVAILABLE = False
    PSUTIL_ERROR = "未安装 psutil：{}".format(e)


# ============================ 内部状态 ============================
_lock = threading.Lock()

_prev_io = {
    "time": None,
    "disk_read": None, "disk_write": None,
    "net_recv": None, "net_sent": None,
}

# 中位数平滑窗口（采样点个数）。1.5 秒采一次，7 点约覆盖 10 秒
_WINDOW = 7
_buf_cpu = deque(maxlen=_WINDOW)
_buf_mem = deque(maxlen=_WINDOW)
_buf_disk = deque(maxlen=_WINDOW)
_buf_net = deque(maxlen=_WINDOW)
_buf_conn = deque(maxlen=_WINDOW)

# CPU 首次采样标记：psutil 首次调用返回 0.0，无意义必须丢弃
_cpu_warmed = False

# 主机静态信息（只读一次）
_static = {}


def _median(buf):
    """取窗口中位数。比均值更抗尖峰，同时保留真实波动。"""
    vals = sorted(v for v in buf if v is not None)
    if not vals:
        return None
    n = len(vals)
    return vals[n // 2] if n % 2 else (vals[n // 2 - 1] + vals[n // 2]) / 2.0


def _read_static():
    """读取不会频繁变化的主机静态信息。"""
    global _static
    if _static:
        return
    try:
        _static = {
            "cpu_count": psutil.cpu_count(logical=True),
            "cpu_count_physical": psutil.cpu_count(logical=False),
            "mem_total_gb": round(psutil.virtual_memory().total / (1024 ** 3), 1),
            "platform": "{} {}".format(
                __import__("platform").system(), __import__("platform").release()),
            "boot_time": time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(psutil.boot_time())),
        }
    except Exception as e:
        _static = {"error": str(e)}


def sample():
    """执行一次采样并写入平滑窗口。由后台循环每 1.5 秒调用一次。

    Returns:
        dict: 本次采样的原始读数（含可能的 None 表示该项不可用）
    """
    if not PSUTIL_AVAILABLE:
        return {"available": False, "error": PSUTIL_ERROR}

    # 注意：_cpu_warmed 是模块级变量，在函数内赋值必须声明 global，
    # 否则 Python 会把它当作局部变量 —— 首次采样标记永远无法生效，
    # 结果是每次采样都走"首次丢弃"分支，CPU 指标永远为 None。
    global _cpu_warmed

    now = time.time()
    out = {"available": True, "error": ""}

    with _lock:
        _read_static()

        # ---------- CPU：非阻塞相对采样 ----------
        try:
            raw = psutil.cpu_percent(interval=None)
            if not _cpu_warmed:
                # 首次调用返回 0.0，不代表真实占用率，丢弃
                _cpu_warmed = True
                raw = None
            else:
                _buf_cpu.append(raw)
            out["cpu"] = raw
        except Exception as e:
            out["cpu"] = None
            out["error"] = "cpu: {}".format(e)

        # ---------- 内存：瞬时值，无需差值 ----------
        try:
            vm = psutil.virtual_memory()
            _buf_mem.append(vm.percent)
            out["mem"] = vm.percent
            out["mem_used_gb"] = round(vm.used / (1024 ** 3), 2)
            out["mem_total_gb"] = round(vm.total / (1024 ** 3), 2)
        except Exception as e:
            out["mem"] = None
            out["error"] = (out["error"] + " mem: " + str(e)).strip()

        # ---------- 磁盘 / 网卡：累计计数器做差值 ----------
        try:
            d = psutil.disk_io_counters()
            n = psutil.net_io_counters()
            if d and n and _prev_io["time"] is not None:
                dt = now - _prev_io["time"]
                if dt > 0.05:      # 防止极短间隔导致速率被放大
                    rd = max(0, d.read_bytes - _prev_io["disk_read"]) / dt
                    wr = max(0, d.write_bytes - _prev_io["disk_write"]) / dt
                    rc = max(0, n.bytes_recv - _prev_io["net_recv"]) / dt
                    sn = max(0, n.bytes_sent - _prev_io["net_sent"]) / dt
                    _buf_disk.append(rd + wr)
                    _buf_net.append(rc + sn)
                    out["disk_bps"] = rd + wr
                    out["net_bps"] = rc + sn
                    # 网卡吞吐同时给出 Mbps，便于与沙箱流量曲线对照
                    out["net_mbps"] = round((rc + sn) * 8 / 1e6, 3)
            if d:
                out["disk_read_total_gb"] = round(d.read_bytes / (1024 ** 3), 2)
                out["disk_write_total_gb"] = round(d.write_bytes / (1024 ** 3), 2)
            _prev_io["time"] = now
            if d:
                _prev_io["disk_read"], _prev_io["disk_write"] = d.read_bytes, d.write_bytes
            if n:
                _prev_io["net_recv"], _prev_io["net_sent"] = n.bytes_recv, n.bytes_sent
        except Exception as e:
            out["error"] = (out["error"] + " io: " + str(e)).strip()

        # ---------- TCP 连接数：可能因权限失败，属可降级项 ----------
        try:
            _buf_conn.append(len(psutil.net_connections(kind="tcp")))
        except Exception:
            # 权限不足或被平台限制时静默跳过（不影响其它指标）
            pass

    return out


def snapshot():
    """返回面向界面的主机指标快照（已做中位数平滑）。

    Returns:
        dict: 含各项指标的平滑值；不可用项为 None。
              同时带 available 标记，供前端区分"真实采集"与"不可用"。
    """
    if not PSUTIL_AVAILABLE:
        return {"available": False, "error": PSUTIL_ERROR, "items": []}

    with _lock:
        cpu = _median(_buf_cpu)
        mem = _median(_buf_mem)
        disk = _median(_buf_disk)
        net = _median(_buf_net)
        conn = _median(_buf_conn)
        static = dict(_static)

    def fmt_bytes(bps):
        if bps is None:
            return None
        if bps < 1024:
            return "{:.0f} B/s".format(bps)
        if bps < 1024 ** 2:
            return "{:.1f} KB/s".format(bps / 1024)
        return "{:.1f} MB/s".format(bps / 1024 ** 2)

    # 磁盘占用（系统盘）
    disk_use = None
    try:
        root = "C:\\" if __import__("os").name == "nt" else "/"
        disk_use = psutil.disk_usage(root).percent
    except Exception as exc:
        # 采集失败时该项返回 None（前端显示 "--"），但不能静默 ——
        # 排查"磁盘占用一直是 --"时需要能在这里看到原因。
        logger.debug("读取磁盘占用失败，本次跳过该项: %s", exc)

    mem_total = static.get("mem_total_gb")
    mem_used = round(mem_total * mem / 100, 2) if (mem_total and mem is not None) else None

    items = [
        {"key": "cpu", "label": "CPU 占用",
         "value": round(cpu, 1) if cpu is not None else None,
         "unit": "%", "detail": "{} 逻辑核心".format(static.get("cpu_count") or "-")},
        {"key": "mem", "label": "内存占用",
         "value": round(mem, 1) if mem is not None else None,
         "unit": "%",
         "detail": "{} / {} GB".format(mem_used if mem_used is not None else "-",
                                       mem_total if mem_total else "-")},
        {"key": "net", "label": "网卡吞吐",
         "value": round(net * 8 / 1e6, 3) if net is not None else None,
         "unit": "Mbps", "detail": fmt_bytes(net) if net is not None else "--"},
        {"key": "disk", "label": "磁盘 IO",
         "value": round(disk / 1024 ** 2, 2) if disk is not None else None,
         "unit": "MB/s", "detail": "读写合计"},
        {"key": "disk_use", "label": "磁盘占用",
         "value": round(disk_use, 1) if disk_use is not None else None,
         "unit": "%", "detail": "系统盘"},
        {"key": "conn", "label": "TCP 连接",
         "value": int(conn) if conn is not None else None,
         "unit": "", "detail": "本机全部 TCP"},
    ]

    return {
        "available": True,
        "error": "",
        "sampled_at": time.strftime("%H:%M:%S"),
        "uptime_hint": static.get("boot_time"),
        "platform": static.get("platform"),
        "items": items,
        "request_avg_ms": request_avg_ms(),
        "request_count": request_count(),
    }


# ============================================================================
#                        请求耗时统计（真实性能指标）
# ============================================================================
# 用途：替换攻击链页原先的 `那个「2~7 秒之间的随机数」`。
# 那个数字每次刷新都在 2~7 秒之间随机跳，是纯随机数；
# 这里改为在 after_request 里记录每次 HTTP 请求的真实耗时，滚动求平均。
# ============================================================================

_req_lock = threading.Lock()
_req_times = deque(maxlen=200)      # 最近 200 次请求耗时（毫秒）
_req_total = 0


def record_request(duration_ms):
    """记录一次请求耗时（由 after_request 钩子调用）。"""
    global _req_total
    with _req_lock:
        _req_times.append(duration_ms)
        _req_total += 1


def request_avg_ms():
    """最近 200 次请求的平均耗时（毫秒），无数据返回 None。"""
    with _req_lock:
        if not _req_times:
            return None
        return round(sum(_req_times) / len(_req_times), 1)


def request_count():
    """累计处理的请求数。"""
    with _req_lock:
        return _req_total
