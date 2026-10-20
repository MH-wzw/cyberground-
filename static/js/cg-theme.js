/* ==========================================================================
   CyberGuard · JS 侧主题色表（v3 · SOC 深炭黑 / 亮翡翠绿）
   ==========================================================================
   为什么需要这个文件：

     CSS 变量只能被 CSS 读到。而 ECharts 的配色、Canvas 的渐变都是写在
     JS 配置里的 —— 设计系统换主题时，这些地方纹丝不动，页面上就会出现
     「文字换成了翡翠绿、图表还是 Indigo」的割裂感。

   本文件是**全站 JS 侧唯一的颜色来源**，取值与 design-system.css 的
   body.theme-dash 令牌（v40 SOC 深炭黑）一一对应。改主题时只需同步
   这一个文件。

   ⚠ v40 换肤的关键变化 —— 深色图表三件套回归：
     1. **轴线与分隔线转浅**：深色底上用 rgba(255,255,255,·) 画网格线。
     2. **面积填充回到 12% 透明**：深底上 12% 亮绿渐变是通透的，
        不会像白底那样糊成色块。
     3. **tooltip 用抬升深灰面板 + 微亮描边**：靠明度差浮出页面。
     4. 数据线用 400 级亮调（翡翠/琥珀/亮红），深底上全部 ≥6:1。

   用法：
     color: CG.c1                     // 主强调（翡翠绿）
     'rgba(' + CG.redRgb + ',.12)'    // 带透明度
     CG.rgba(CG.greenRgb, .3)
   ========================================================================== */
(function (w) {
  'use strict';

  var CG = {
    /* ---- 双强调：翡翠绿（交互/数据线） + 青碧（第二序列） ---- */
    c1:        '#34D399',
    c1Rgb:     '52,211,153',
    c1Hi:      '#6EE7B7',
    c1Dim:     '#10B981',
    c2:        '#2DD4BF',
    c2Rgb:     '45,212,191',

    /* ---- 语义色（400 级亮调，深底上 ≥6:1） ---- */
    green:     '#34D399',
    greenRgb:  '52,211,153',
    orange:    '#FBBF24',
    orangeRgb: '251,191,36',
    red:       '#F87171',
    redRgb:    '248,113,113',
    dangerText:'#F87171',
    pink:      '#F472B6',
    purple:    '#A78BFA',
    info:      '#38BDF8',
    infoRgb:   '56,189,248',

    /* ---- 中性文字（白 + 浅灰体系） ---- */
    text:      '#F2F5F3',
    text2:     '#B9C1C9',
    muted:     '#98A2AD',
    faint:     '#7D8894',

    /* ---- 面与线 ----
       panel 为抬升深灰（tooltip 等浮层），
       line / axis / split 全部转向微亮白调。 */
    panel:     '#1B2129',
    panelLine: '#2B333D',
    line:      '#232B34',
    axis:      '#323C48',
    split:     'rgba(255,255,255,.06)',

    /* ---- 面积图填充：深底回到 12% ---- */
    area:      function (rgb, a) { return 'rgba(' + rgb + ',' + (a || 0.12) + ')'; },

    /* ---- 工具 ---- */
    rgba: function (rgb, a) { return 'rgba(' + rgb + ',' + a + ')'; },

    /**
     * 从 CSS 变量实时读取（主题切换时应改用这个而不是上面的常量）。
     * 目前全部值在此处硬编码，与 design-system.css 保持同步；
     * 保留此方法以备后续做真正的运行时换肤。
     */
    fromCss: function (name, fallback) {
      var v = getComputedStyle(document.body).getPropertyValue(name);
      return (v || '').trim() || fallback;
    }
  };

  w.CG = CG;

  /* 表格 / 图例里按语义取色的便捷入口 */
  w.CG_SEMANTIC = { ok: CG.green, warn: CG.orange, crit: CG.red, info: CG.c1 };

  /* ECharts tooltip 的统一样式：深底用抬升深灰 + 微亮描边浮出页面 */
  w.CG_TOOLTIP = {
    backgroundColor: CG.panel,
    borderColor: CG.panelLine,
    borderWidth: 1,
    padding: [8, 12],
    textStyle: { color: CG.text, fontSize: 12 },
    extraCssText: 'box-shadow:0 10px 25px -5px rgba(0,0,0,.55),0 8px 10px -6px rgba(0,0,0,.4);' +
                  'border-radius:10px;'
  };

  /* ECharts 直角系坐标轴的统一样式（避免每个图表各自写一套灰度） */
  w.CG_AXIS = {
    axisLine:   { lineStyle: { color: CG.axis } },
    axisTick:   { show: false },
    axisLabel:  { color: CG.muted, fontSize: 11 },
    splitLine:  { lineStyle: { color: CG.split } }
  };
})(window);
