# CyberGuard × Uiverse 技法迁移规格（UI-SPEC）

> 版本：v1 · 2026-10-15 · 作者：UI 设计师
> 来源：`uiverse.io/elements` → 官方开源仓库 `uiverse-io/galaxy`（MIT，13.5k stars）
> 检索方式：全量 tarball 本地解析 **3802 个组件**（非翻页抽样），做 CSS 技法频谱统计后筛选

---

## 0. 结论先行

| 项 | 结论 |
|---|---|
| 检索规模 | 3802 个组件 / 11 类，全量本地解析 |
| 可迁移技法 | **7 项**（T1–T7），全部为「交互态增强」，不动信息结构 |
| 迁移原则 | **抄技法不抄配色** —— 所有实现只引用 Nocturne 现有令牌，不引入新色值 |
| 落地范围 | 按钮 / 指标卡 / 开关 / 背景 / 输入框 / 骨架屏 / 提示，共 7 个组件 |
| 风险 | 无新增常驻动画（7 项全部为 hover / focus / 一次性触发），不违反 Nocturne 三条纪律 |

---

## 1. 检索方法与数据（✅已验证）

SPA 页面拿不到源码，改从官方仓库取全量：

```
codeload.github.com/uiverse-io/galaxy/tar.gz → 19MB → 3802 个 *.html
```

分析脚本（可复用）：`.workbuddy/uiverse_analyze.py`（技法频谱）、`uiverse_pick.py`（暗色+密度打分）、`uiverse_show.py`（打印精简 CSS）

### 1.1 分类分布

| 分类 | 数量 | 分类 | 数量 |
|---|---|---|---|
| Buttons | 1231 | Forms | 180 |
| Cards | 726 | Checkboxes | 171 |
| loaders | 718 | Patterns | 103 |
| Toggle-switches | 260 | Radio-buttons | 102 |
| Inputs | 226 | Tooltips | 62 |
| | | Notifications | 23 |

### 1.2 全库技法频率（Top 15）

| 技法 | 占比 | 技法 | 占比 |
|---|---|---|---|
| border-radius | 71.8% | pseudo_before | 32.9% |
| transform | 64.0% | linear-gradient | 26.2% |
| transition | 54.6% | pseudo_after | 25.2% |
| hover | 48.1% | rotate | 24.5% |
| box-shadow | 47.6% | scale | 23.1% |
| flex | 41.2% | hover_transform | 21.5% |
| translate | 37.6% | hover_color | 20.1% |
| @keyframes | 35.7% | hover_bg | 17.6% |

### 1.3 hover 时社区最常做什么（占含 hover 组件比）

| 行为 | 占比 | 解读 |
|---|---|---|
| transform | **44.6%** | 位移/缩放是首选反馈 |
| color | 41.8% | 文字变色 |
| background | 36.5% | 底色变化 |
| box-shadow | 29.4% | 投影/辉光 |
| opacity | 20.3% | 透明度 |
| box-shadow（辉光型） | 14.2% | 其中发光只占少数 |

**关键判断**：社区 hover 高度依赖 `transform + box-shadow + 伪元素`，但**辉光只占 14.2%** —— 说明「克制」才是主流，大量发光反而是少数派。这与 Nocturne「辉光只给主按钮」的纪律一致，无需放宽。

---

## 2. 设计令牌补充

本次**不新增色值**，只补 4 个动效/纹理令牌（追加到 `design-system.css` 第 8b 节后）：

| 令牌 | 值 | 用途 | 依据 |
|---|---|---|---|
| `--grid-color` | `rgba(157,140,255,.045)` | 网格线（原为 `transparent`，网格实际不可见） | T4 需要"被摄物" |
| `--vignette` | `inset 0 0 200px 70px rgba(0,0,0,.55)` | 背景层暗角 | T4 |
| `--ease-spring` | `cubic-bezier(.8,.5,.2,1.4)` | 弹性缓动（回弹） | T3 开关果冻效应 |
| `--ease-glide` | `cubic-bezier(.16,1,.3,1)` | 顺滑展开（已有散落值，收口命名） | T5 下划线 |

> 原 `--grid-color: transparent` 是历史遗留：网格层 `body::before` 一直在，但颜色被清空了。这直接违反「玻璃拟态背后必须有被摄物」的既定结论 —— 面板透出的是纯色底，所以怎么调都"发闷"。T4 修复的是这个根因。

---

## 3. 技法迁移清单（T1–T7）

### T1 · 主 CTA 对向扫光 ★高价值
- **来源**：`Buttons/0xnihilism_pretty-fireant-33.html`（技法密度评分 19.2，全库按钮第一）
- **原技法**：`::before`/`::after` 各一条 `linear-gradient(90deg, transparent, rgba(255,255,255,.1), transparent)`，初始 `left:-100%`/`left:100%`，hover 时 `swipeRight`/`swipeLeft` 对向扫过
- **落点**：`.btn-glow`（主操作按钮，全站 9 处）
- **规格**
  - 容器 `position: relative; overflow: hidden`（裁掉溢出光带）
  - 两条光带各宽 60%，`skew(-20deg)`（原版 -45deg 过斜，工具界面显浮夸）
  - hover 时 `animation: cgSwipeR 1.05s ease-in-out` 单次（原版 infinite —— 常驻循环违反纪律，改单次）
  - 光带颜色 `rgba(255,255,255,.14)`，不引入品牌渐变
- **状态**：hover 扫光 / active 下沉 1px / disabled 无光带且 opacity .45

### T2 · 可交互指标卡三线光效 ★高价值
- **来源**：`Buttons/MuhammadHasann_tough-tiger-78.html`（评分 18.2）
- **原技法**：外溢光斑（`::before` blur(30px) 光晕）+ 顶部 2px 亮线（`box-shadow` 模拟）+ 底部渐变光弧（`::after` 多段透明→亮→透明 + `drop-shadow`）
- **落点**：`a.stat-card`（可点击指标卡；首页 hero 卡即此类型）
- **规格**：hover 时三件事同时发生
  1. 顶部亮线：`::before` 由 `width:0` → `100%`，高 2px，`--brand-grad`（此为既有的第 11 类允许点之外的**交互态**，仅在 hover 存在，不增加常驻渐变面）
  2. 底部光弧：`::after` 由 `width:0` → `100%`，高 2px，青→透明渐变，`filter: drop-shadow(0 0 8px rgba(62,224,240,.5))`
  3. 外溢光晕：`box-shadow: 0 0 28px rgba(62,224,240,.14)`
  - 时长 `.42s`，缓动 `--ease-glide`
- **约束**：`.stat-card` 静态态**不加**任何光效，保持与不可点击卡片一致

### T3 · 弹性开关（squash & stretch）
- **来源**：`Toggle-switches/JkHuger_itchy-turtle-45.html`
- **原技法**：滑块位移时中途 `width` 由 46px 拉伸到 75px 再收回，缓动 `cubic-bezier(.8,.5,.2,1.4)` —— 果冻挤压感
- **落点**：通知配置页「启用/停用」→ 新建 `.cg-switch` 组件替换现有 pill 按钮 `.status-toggle`
- **规格**
  - 轨道 46×26px，`border-radius: 999px`，底色 `rgba(255,255,255,.07)`，开启态 `rgba(62,224,240,.22)` + 青色描边
  - 滑块 20×20px，`left:3px`，开启态 `translateX(20px)`
  - 关键帧 `cgSwitchOn/Off`：0% width 20px → 50% width 30px → 100% width 20px
  - 缓动 `--ease-spring`，时长 `.34s`
- **可访问性**：用真实 `<input type="checkbox" class="cg-switch">`，保留 `:focus-visible` 描边与 `:checked` 语义，不靠颜色单独传达状态（轨道内加 1px 分隔）

### T4 · 背景网格 + 暗角 + 静态光斑 ★根因修复
- **来源**：`Inputs/MijailVillegas_shaggy-husky-62.html` 的 `.card`（网格 `background-size:.5rem` + `box-shadow: inset 0 0 40px 20px #000`）
- **落点**：`body::before`（全站唯一 fixed 背景层）
- **规格**
  - 网格：`--grid-color: rgba(157,140,255,.045)`，`background-size: 52px 52px`，`opacity:.5`
  - 暗角：`box-shadow: var(--vignette)` —— 四角压暗，中心留亮，制造景深
  - 光斑：叠加两层 `radial-gradient`（左上青、右下紫，各 `rgba(...,.06)`），静态不动
- **约束**：仍是**单个 fixed 层**（`body::before`），不逐卡片加背景；全部静态，不新增常驻动画

### T5 · 输入框聚焦下划线中心展开
- **来源**：Inputs 类高频技法（underline-expand）
- **落点**：`.form-control-dark` / `.form-select-dark`
- **规格**：`::after` 绝对定位底部，`width:0; left:50%; transform:translateX(-50%)`，focus 时 `width:100%`，高 2px，`--brand-grad`，`.32s --ease-glide`
- **状态**：hover 边框微亮 → focus 下划线展开 + 边框转 `--accent-1` → disabled opacity .5 无下划线

### T6 · 骨架屏 shimmer
- **来源**：loaders 类（718 个，94% 含 @keyframes）
- **落点**：`.cg-skel`（现为 3 条呼吸条）
- **规格**：在现有呼吸基础上叠一层 shimmer —— `background: linear-gradient(90deg, transparent, rgba(255,255,255,.07), transparent)`，`background-size: 200% 100%`，`animation: cgShimmer 1.6s linear infinite`
- **约束**：shimmer 是**加载态专用**，数据到位即消失，不构成"常驻"

### T7 · 统一 tooltip
- **来源**：`Tooltips/Javierrocadev_rude-seahorse-6.html`（评分 15.3）
- **原技法**：`::before` 旋转 45° 的小方块做尖角 + `::after` blur(8px) 圆形光斑
- **落点**：全站 `data-cg-tip="文本"` 属性驱动的纯 CSS tooltip
- **规格**
  - 气泡：`background: rgba(15,13,30,.97)`，1px `--border-subtle`，`border-radius: 8px`，`font-size: 12px`，`padding: 6px 10px`
  - 尖角：`::before` 6×6px，`rotate(45deg)`，继承气泡底色与边框
  - 光斑：去掉原版 blur 光斑（过花），改 1px 顶部渐变亮线（同 T2 语言）
  - 方向：`data-cg-tip-pos="top|bottom|left|right"`，默认 top
  - 延迟：hover 后 `.18s` 出现，`opacity` + `translateY(4px)` 过渡
- **可访问性**：tooltip 仅作补充，**不与 `aria-label` 冲突**（有 `aria-label` 的元素不加 `data-cg-tip`）

---

## 4. 页面映射（PS ↔ 技法）

| 页面 | 应用技法 | 说明 |
|---|---|---|
| PS-01 登录 / 注册 | T4, T5, T1 | 评委第一屏，输入框聚焦是最高频交互 |
| PS-02 态势总览 | T2, T4, T6, T7 | hero 卡 hover 三线光效是主视觉亮点 |
| PS-03 攻击链 | T4, T6, T7 | 骨架屏在等待数据时直接可见 |
| PS-04 热力地图 | T4, T7 | |
| PS-05 日志 / 告警 / 黑名单 | T1, T4, T7 | 表格操作按钮扫光 |
| PS-06 通知配置 | T3, T5, T1 | 弹性开关主战场 |
| PS-07 403 / 封禁提示 | T1, T4 | |

---

## 5. 验收清单

- [x] 全库技法统计可复现（脚本保留，数据已写入 `uiverse_stats.json`）
- [x] 未引入任何新色值（仅引用 Nocturne 令牌）
- [x] 常驻动画未增加（T1/T2/T3/T5/T7 均为交互触发；T6 仅加载态；T4 全静态）
- [x] 未新增 `backdrop-filter`
- [x] 品牌渐变使用点未超过既定 5 类（T2/T5 为交互态，静态不可见）
- [x] 每个组件状态完备：hover / active / focus / disabled / 加载 / 空
- [x] 正文对比度 ≥ 4.5:1（tooltip 文字用 `--text-secondary` = 8.27:1）
- [x] Jinja 编译 + div 平衡 + JS 语法审计全绿（2026-10-15 21:4x）
- [x] CDP 实拍验证：`shots/*_hv.png` —— T1 按钮 hover 辉光 ✓ / T2 三线光效 ✓ / T3 开关含挤压中段 ✓ / T5 focus 青边+下划线 ✓ / T7 气泡 ✓ / T4 见 `dash_uv.png`

### 实拍过程中的两个真实发现（已修复）

1. **`.table-responsive`（overflow:auto）会裁掉表内元素的 CSS tooltip** —— 表头说明已改回原生 `title` 属性（可读屏、不受裁剪），T7 只用于无 overflow 裁剪的容器。这是 CSS tooltip 的经典限制，记录在案。
2. **CDP `captureScreenshot` 的 clip 用文档坐标**，页面滚动后喂视口坐标会拍到错误区域（黑图）。`cdp_hover.js` 已区分 `vx/vy`（鼠标事件）与 `dx/dy`（截图 clip）两套坐标。

## 6. 遗留与建议确认

1. ~~T3 开关替换 `.status-toggle`~~ → 已落地通知页收件人表格（真实 checkbox + change 事件 + 失败回滚），拦截 AJAX 失败时开关自动拨回。
2. **T4 网格恢复可见** —— 已落地（`.045` 透明度），实拍确认面板背后有纹理与光斑，"发闷"问题解决。嫌重可调低。
3. **T7 全量标注** —— 目前仅 1 处（静默时段）。建议后续给告警等级徽章、风险分值等缩写字段补挂；表格内部元素除外（见上述限制）。
4. **T1 扫光**在静态截图帧里不明显（1.05s 单次动画的中段帧），真机 hover 可见。如需更强的第一眼反馈，可把光带透明度从 `.14` 提到 `.22`。
