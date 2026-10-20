/**
 * ===========================================================================
 *  CyberGuard — 前端公共脚本
 * ===========================================================================
 *  各页面统一引入，提供三件事：
 *    1. CSRF 令牌自动注入（jQuery $.ajax / 原生 fetch 两条通道）
 *    2. 主题化 toast 通知（替代原生 alert，避免系统白底弹窗破坏暗色演示）
 *    3. 主题化确认弹窗 cgConfirm（返回 Promise，替代原生 confirm）
 *
 *  用法：
 *    <meta name="csrf-token" content="{{ csrf_token }}">
 *    <script src="/static/js/cyberguard.js"></script>
 *
 *  设计说明：
 *    权限判断始终在服务端完成。前端的按钮隐藏 / 禁用只是体验优化，
 *    不构成安全边界；即使有人手动构造请求，服务端依然会返回 401/403。
 * ===========================================================================
 */
(function () {
  'use strict';

  // ------------------------------------------------------------------
  // 1) CSRF 令牌
  // ------------------------------------------------------------------
  var CSRF = '';
  var meta = document.querySelector('meta[name="csrf-token"]');
  if (meta) CSRF = meta.getAttribute('content') || '';

  // jQuery 通道：统一给所有写请求加上 X-CSRF-Token 头
  if (window.jQuery) {
    window.jQuery.ajaxSetup({
      headers: CSRF ? { 'X-CSRF-Token': CSRF } : {}
    });
  }

  // fetch 通道：包装一层，自动补上 CSRF 头
  var nativeFetch = window.fetch ? window.fetch.bind(window) : null;
  if (nativeFetch) {
    window.fetch = function (input, init) {
      init = init || {};
      var method = (init.method || (typeof input === 'object' && input.method) || 'GET').toUpperCase();
      if (['POST', 'PUT', 'PATCH', 'DELETE'].indexOf(method) >= 0 && CSRF) {
        var headers = new Headers(init.headers || (typeof input === 'object' ? input.headers : null) || {});
        if (!headers.has('X-CSRF-Token')) headers.set('X-CSRF-Token', CSRF);
        init.headers = headers;
      }
      return nativeFetch(input, init);
    };
  }

  window.CG_CSRF = CSRF;

  // ------------------------------------------------------------------
  // 2) 主题化 toast
  // ------------------------------------------------------------------
  function toastWrap() {
    var w = document.getElementById('cgToastWrap');
    if (!w) {
      w = document.createElement('div');
      w.id = 'cgToastWrap';
      w.className = 'cg-toast-wrap';
      document.body.appendChild(w);
    }
    return w;
  }

  /**
   * 显示一条主题化通知
   * @param {string} msg  文本
   * @param {string} kind ok | warn | err | ''（默认蓝色信息）
   * @param {number} ms   停留毫秒数
   */
  var TOAST_MAX = 3;          // 同屏最多 3 条，超出挤掉最旧的一条
  function cgToast(msg, kind, ms) {
    var w = toastWrap();
    // 堆叠上限：连接抖动 / 批量操作会连续弹多条，无限堆叠会盖住半个屏幕。
    // 这里直接淘汰最旧的一条（cgToast 都是"知情即可"的提示，无处置语义）。
    while (w.children.length >= TOAST_MAX) w.removeChild(w.firstChild);
    var el = document.createElement('div');
    el.className = 'cg-toast ' + (kind || '');
    el.textContent = msg;
    w.appendChild(el);
    setTimeout(function () {
      el.style.opacity = '0';
      el.style.transition = 'opacity .3s';
      setTimeout(function () { el.remove(); }, 320);
    }, ms || 2600);
  }
  window.cgToast = cgToast;
  // 若某页面早已自定义同名函数（历史实现），此处不覆盖它，保持行为一致
  if (typeof window.cgToast === 'function' && !window.__cgToastFromCommon) {
    window.__cgToastFromCommon = true;
  }

  // ------------------------------------------------------------------
  // 3) 主题化确认弹窗（替代原生 confirm）
  // ------------------------------------------------------------------
  function cgConfirm(message, opts) {
    opts = opts || {};
    return new Promise(function (resolve) {
      var mask = document.createElement('div');
      mask.className = 'cg-confirm-mask';
      mask.innerHTML =
        '<div class="cg-confirm-box" role="dialog" aria-modal="true">' +
        '  <div class="cg-confirm-ico">' + (opts.icon || '') + '</div>' +
        '  <div class="cg-confirm-title">' + (opts.title || '请确认操作') + '</div>' +
        '  <div class="cg-confirm-msg"></div>' +
        '  <div class="cg-confirm-actions">' +
        '    <button class="cg-btn-ghost" data-act="cancel">取消</button>' +
        '    <button class="cg-btn-solid' + (opts.danger ? ' danger' : '') + '" data-act="ok">' +
             (opts.okText || '确定') + '</button>' +
        '  </div>' +
        '</div>';
      // 用 textContent 写入消息，避免把用户输入当 HTML 解析（防 XSS）
      mask.querySelector('.cg-confirm-msg').textContent = message;
      document.body.appendChild(mask);

      function close(val) {
        mask.style.opacity = '0';
        setTimeout(function () { mask.remove(); }, 220);
        document.removeEventListener('keydown', onKey);
        resolve(val);
      }
      function onKey(e) { if (e.key === 'Escape') close(false); }

      mask.querySelector('[data-act="cancel"]').onclick = function () { close(false); };
      mask.querySelector('[data-act="ok"]').onclick = function () { close(true); };
      mask.onclick = function (e) { if (e.target === mask) close(false); };
      document.addEventListener('keydown', onKey);
      var okBtn = mask.querySelector('[data-act="ok"]');
      if (okBtn) okBtn.focus();
    });
  }
  window.cgConfirm = cgConfirm;

  // ------------------------------------------------------------------
  // 4) 攻击浪潮阶段徽章
  // ------------------------------------------------------------------
  // 浪潮结构下"平静期"会持续一两分钟、画面上几乎没有攻击，
  // 必须让当前阶段始终可见，否则使用者会误以为系统停止工作。
  // 首页等页面通过 WebSocket 实时推送阶段，这里同时提供一个轮询兜底，
  // 保证没有实时通道的页面（日志/告警/黑名单/用户管理）也能正确显示。
  var PHASE_LABEL = { calm: '平静期', rise: '攀升期', surge: '突袭期', decay: '消退期' };

  function cgUpdateWaveBadge(wave) {
    // 断线期间不得覆盖徽章 —— 本函数会重写 className，
    // 若此时放行，15 秒一次的轮询会把"实时连接已断开"的提示抹掉，
    // 于是断线状态看起来又像"一切正常"了。等重连后由 cgSetConnState
    // 主动调回本函数刷新。
    if (_cgConnLost) return;
    if (!wave || !wave.phase) return;
    var el = document.getElementById('waveBadge');
    var txt = document.getElementById('waveText');
    if (!el || !txt) return;

    // 阶段名 + 剩余秒数：让"还要等多久"也可见，而不是干等
    var left = wave.left_seconds || wave.left_ticks || 0;
    txt.textContent = (wave.label || PHASE_LABEL[wave.phase] || wave.phase) +
                      (left ? ' · ' + Math.round(left) + 's' : '');

    el.className = 'wave-badge phase-' + wave.phase;
    el.title = '当前攻击浪潮阶段：' + (wave.label || '') +
               '\n本阶段剩余约 ' + Math.round(left) + ' 秒' +
               '\n已观测到 ' + (wave.waves || 0) + ' 波完整攻击' +
               '\n肉鸡池规模 ' + (wave.botnet_size || 0) + ' 个源地址' +
               (wave.phase === 'calm' ? '\n（平静期为正常状态，真实 DDoS 大部分时间静默）' : '');
  }
  window.cgUpdateWaveBadge = cgUpdateWaveBadge;

  function cgPollWave() {
    if (!document.getElementById('waveBadge')) return;
    fetch('/api/ddos/wave')
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (w) { if (w) cgUpdateWaveBadge(w); })
      .catch(function () { /* 忽略：徽章失败不影响主功能 */ });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      cgPollWave();
      setInterval(cgPollWave, 15000);
    });
  } else {
    cgPollWave();
    setInterval(cgPollWave, 15000);
  }

  // ------------------------------------------------------------------
  // 4.5) 实时连接状态可见化（WebSocket 断线提示）
  // ------------------------------------------------------------------
  // 背景：态势大屏的数据由 WebSocket 推送。连接一旦断开，画面会静止在
  //       最后一帧 —— 而静止与平静期没有攻击在观感上完全一致。
  //       值班人会把数据通道已断误读为一切正常，这在安全运营中很危险。
  //       因此断线必须在界面上明确可见，而不只是打一条控制台日志。
  //
  // 实现：由各页面的 socket.on('connect'/'disconnect') 调用本函数，
  //       统一维护 body 与浪潮徽章上的状态类。
  var _cgConnLost = false;

  function cgSetConnState(connected, detail) {
    var badge = document.getElementById('waveBadge');
    var txt = document.getElementById('waveText');

    if (connected) {
      // 恢复：移除断线态，交由 cgUpdateWaveBadge 重新渲染正常阶段
      _cgConnLost = false;
      document.body.classList.remove('conn-lost');
      if (badge) badge.classList.remove('conn-lost');
      if (txt) txt.textContent = '连接中';
      cgPollWave();          // 立即拉一次当前阶段，避免停留在连接中
      return;
    }

    // 断线：只提示一次，避免重连循环里反复弹窗
    var firstTime = !_cgConnLost;
    _cgConnLost = true;
    document.body.classList.add('conn-lost');
    if (badge) {
      // 清掉阶段类，否则会被阶段色覆盖，看起来一切正常
      badge.className = 'wave-badge conn-lost';
    }
    if (txt) txt.textContent = '实时连接已断开';
    if (badge) {
      badge.title = '实时数据通道已断开，页面显示的是最后一次收到的数据'
        + (detail ? '（' + detail + '）' : '')
        + '。系统会自动重连。';
    }
    if (firstTime) {
      cgToast('实时连接已断开，当前画面为最后一次收到的数据，正在自动重连…', 'err');
    }
  }

  window.cgSetConnState = cgSetConnState;

  // ------------------------------------------------------------------
  // 5) 未登录 / 权限不足的统一处理
  // ------------------------------------------------------------------
  // 任一接口返回 401 说明会话已失效（例如服务重启导致随机密钥变更），
  // 直接引导回登录页，而不是让页面停在"加载中..."。
  if (window.jQuery) {
    window.jQuery(document).ajaxError(function (_e, xhr) {
      if (xhr && xhr.status === 401) {
        cgToast('登录状态已失效，正在返回登录页...', 'warn');
        setTimeout(function () { window.location.href = '/login'; }, 1200);
      }
    });
  }

  // ------------------------------------------------------------------
  // 6) ECharts 统一动画参数
  // ------------------------------------------------------------------
  // 为什么需要它：
  //   ECharts 的默认 animationDuration 是 1000ms。本系统的图表由
  //   WebSocket 每 1.5 秒推一次数据 —— 也就是说上一段出场动画还没走完，
  //   下一次 setOption 就来了，图表永远处于"画到一半被打断"的状态，
  //   观感拖沓、且高频重绘白耗 GPU。
  //   统一压到 600ms 出场 / 300ms 更新，并固定缓动曲线（cubicOut），
  //   让全站图表有同一种"手感"。
  //
  // 为什么包装 echarts.init 而不是逐处改 setOption：
  //   图表散落在 6 个模板的内联脚本里，逐处加参数等于把同一个常量
  //   抄十几遍，将来改一次要改十几处（正是"补丁残留"的成因）。
  //   包装 init 一次性覆盖全站，且对调用方完全透明。
  //
  // 时序：echarts 由各页在 {% block head_extra %} 里引入，晚于本文件，
  //       因此这里不能立即执行 —— 用 DOMContentLoaded + 轮询兜底。
  function cgPatchECharts() {
    if (window.__cgEchartsPatched) return true;
    if (!window.echarts || typeof window.echarts.init !== 'function') return false;
    var _init = window.echarts.init;
    window.echarts.init = function () {
      var inst = _init.apply(this, arguments);
      var _setOption = inst.setOption;
      inst.setOption = function (opt) {
        if (opt && typeof opt === 'object' && !Array.isArray(opt)) {
          if (opt.animationDuration === undefined) opt.animationDuration = 600;
          if (opt.animationDurationUpdate === undefined) opt.animationDurationUpdate = 300;
          if (opt.animationEasing === undefined) opt.animationEasing = 'cubicOut';
          if (opt.animationEasingUpdate === undefined) opt.animationEasingUpdate = 'cubicOut';
        }
        return _setOption.apply(inst, arguments);
      };
      return inst;
    };
    window.__cgEchartsPatched = true;
    return true;
  }
  window.cgPatchECharts = cgPatchECharts;
  if (!cgPatchECharts()) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', cgPatchECharts);
    }
    var _echTries = 0;
    var _echTimer = setInterval(function () {
      if (cgPatchECharts() || ++_echTries > 60) clearInterval(_echTimer);
    }, 50);
  }

  // ------------------------------------------------------------------
  // 主题色读取 —— 供 JS 里的图表使用
  // ------------------------------------------------------------------
  // 为什么需要它：
  //   ECharts 的颜色是写在 JS 配置里的，**读不到 CSS 变量**。
  //   设计系统换成低饱和配色后，图表仍然用着旧的亮蓝（#38bdf8），
  //   于是页面上出现"文字是石板蓝、图表是荧光蓝"的割裂感。
  //   这里把 CSS 变量读出来交给图表，保证全站配色只有一个来源。
  //
  // 用法：
  //   const C = cgTheme();
  //   color: C.accent, C.ok, C.warn, C.crit,
  //   axis: C.axis, split: C.split, text: C.text, faint: C.faint
  var THEME_CACHE = null;
  window.cgTheme = function () {
    if (THEME_CACHE) return THEME_CACHE;
    var cs = getComputedStyle(document.body);
    function v(name, dflt) {
      var x = (cs.getPropertyValue(name) || '').trim();
      return x || dflt;
    }
    THEME_CACHE = {
      accent:   v('--accent-blue', '#6b8cae'),
      accentDim:v('--accent-blue-dim', '#4a6280'),
      ok:       v('--accent-green', '#5f9e7d'),
      warn:     v('--accent-orange', '#b8934e'),
      crit:     v('--accent-red', '#b5625f'),
      danger:   v('--danger-text', '#c97b78'),
      purple:   v('--accent-purple', '#7d7396'),
      text:     v('--text-primary', '#f2f2f3'),
      body:     v('--text-secondary', '#a8a8ad'),
      faint:    v('--text-faint', '#7a7a83'),
      axis:     v('--border-subtle', '#232326'),
      split:    v('--line-soft', '#1c1c1f'),
      sunken:   v('--surface-sunken', '#0f0f11'),
      card:     v('--bg-card', '#131315'),
      font:     v('--font-mono', 'monospace')
    };
    return THEME_CACHE;
  };
})();

/* ==========================================================================
   底部遥测条（cg-ticker）
   --------------------------------------------------------------------------
   历史问题：base.html 的 #tk* 占位从未被任何代码更新，永远显示 "--"。
   现由本模块统一驱动：三个轻量 HTTP 轮询，全站所有页面共用，
   不依赖各页自己的 WebSocket（日志/告警等无 Socket 页面也能读到数据）。
     · /api/ddos/state → 引擎/阶段/连接/流量
     · /api/stats      → 告警队列 / 封禁 IP（SQLite 真实计数）
     · /api/host       → CPU / 内存（psutil 真实采集）
   节拍 6 秒：遥测条是氛围层，不追 1.5 秒的实时节拍。
   ========================================================================== */
(function () {
  'use strict';

  var PHASES = { calm: '平静期', rise: '攀升期', surge: '突袭期', decay: '消退期' };

  function set(id, v) {
    var el = document.getElementById(id);
    if (el) el.textContent = v;
  }

  function hostVal(h, key) {
    if (!h || !Array.isArray(h.items)) return null;
    var it = h.items.filter(function (x) { return x.key === key; })[0];
    return it && typeof it.value === 'number' ? it.value : null;
  }

  function poll() {
    if (!document.getElementById('tkEngine')) return;   // 无遥测条（公共页）
    Promise.all([
      fetch('/api/ddos/state').then(function (r) { return r.ok ? r.json() : null; }),
      fetch('/api/stats').then(function (r) { return r.ok ? r.json() : null; }),
      fetch('/api/host').then(function (r) { return r.ok ? r.json() : null; })
    ]).then(function (rs) {
      var st = rs[0], db = rs[1], host = rs[2];
      if (!st && !db) throw new Error('empty');
      set('tkEngine', '运行中');
      if (st && st.stats) {
        var s = st.stats;
        set('tkConns', s.active_connections != null ? s.active_connections : '--');
        set('tkTraffic', s.total_bandwidth_mbps != null ? s.total_bandwidth_mbps : '--');
      }
      if (st && st.wave) {
        var ph = PHASES[st.wave.phase] || st.wave.phase || '--';
        var left = st.wave.left != null ? '·' + Math.max(1, Math.round(st.wave.left * 1.5)) + 's' : '';
        set('tkWave', ph + left);
      }
      if (db) {
        set('tkAlerts', db.total_alerts != null ? db.total_alerts : '--');
        set('tkBans', db.blocked_ips != null ? db.blocked_ips : '--');
      }
      var cpu = hostVal(host, 'cpu'), mem = hostVal(host, 'mem');
      set('tkCpu', cpu != null ? cpu.toFixed(0) + '%' : '--');
      set('tkMem', mem != null ? mem.toFixed(0) + '%' : '--');
    }).catch(function () {
      set('tkEngine', '连接中断');
    });
  }

  function start() {
    poll();
    setInterval(poll, 6000);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else { start(); }
})();
