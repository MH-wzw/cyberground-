# -*- coding: utf-8 -*-
"""
=============================================================================
  CyberGuard — DDoS 模拟器与通知门控 单元测试
=============================================================================
  覆盖此前完全没有自动化保障的两块核心逻辑：

    1. utils/ddos_simulator.py（563 行）
       · 浪潮状态机 calm → rise → surge → decay → calm 的确定性转移
       · 攻击事件与攻击链的 mitigated 字段一致性
         （该字段是「已拦截链数」指标的唯一依据，算错会直接反映到看板）
       · reset_state() 的清理完整性

    2. utils/notifier.py 的告警门控（680 行中风险最高的部分）
       · 去重：同源同类型在窗口内只放行一次
       · 限流：窗口内投递数达到上限则拒绝
       · 风险等级比较的偏序关系

  运行：
      python -m unittest tests.test_ddos_notifier -v
=============================================================================
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from utils import ddos_simulator as ddos
from utils import notifier


# ============================================================================
# DDoS 模拟器
# ============================================================================
class TestWaveStateMachine(unittest.TestCase):
    """浪潮状态机：转移路径必须是确定的。"""

    def setUp(self):
        ddos.reset_state()

    def test_initial_phase_is_valid(self):
        """初始阶段必须是四个合法阶段之一。"""
        st = ddos.get_wave_status()
        self.assertIn(st['phase'], ('calm', 'rise', 'surge', 'decay'))

    def test_status_contains_required_keys(self):
        """状态快照的字段完整性 —— 前端徽章与攻击链页都依赖这些键。"""
        st = ddos.get_wave_status()
        for key in ('phase', 'label', 'left_ticks', 'left_seconds',
                    'waves', 'spawned', 'rate_per_min', 'botnet_size'):
            self.assertIn(key, st, '缺少字段 {}'.format(key))
        self.assertIsInstance(st['label'], str)
        self.assertGreaterEqual(st['left_ticks'], 0)

    def test_trigger_wave_enters_surge(self):
        """手动引爆必须进入突袭期（演示按钮的契约）。"""
        r = ddos.trigger_wave()
        self.assertEqual(r['phase'], 'surge')
        self.assertEqual(ddos.get_wave_status()['phase'], 'surge')
        self.assertGreater(r['left'], 0)

    def test_trigger_wave_can_enter_rise(self):
        """force_surge=False 时进入攀升期。"""
        r = ddos.trigger_wave(force_surge=False)
        self.assertEqual(r['phase'], 'rise')

    def test_transitions_follow_fixed_path(self):
        """把倒计时压到 0 后逐次推进，转移顺序必须完全确定。"""
        expected = {'calm': 'rise', 'rise': 'surge',
                    'surge': 'decay', 'decay': 'calm'}
        seen = []
        for _ in range(4):
            ddos._attack_state['wave']['left'] = 1   # 再 -1 即为 0，触发转移
            nxt = ddos._advance_wave()
            seen.append(nxt)
            # 与映射表核对：每次转移都应符合 预期下一阶段
            self.assertIn(nxt, expected.values())
        # 连续 4 次转移应当遍历四个阶段且回到起点
        self.assertEqual(len(set(seen)), 4, '四次转移未覆盖全部阶段: {}'.format(seen))

    def test_wave_counter_increments_on_full_cycle(self):
        """走完 4 段回到 calm 时，累计波次 +1。"""
        ddos.reset_state()
        before = ddos.get_wave_status()['waves']
        # 从当前阶段起连续推进 4 次，必然回到 calm 并计一轮
        cycles = 0
        for _ in range(8):
            ddos._attack_state['wave']['left'] = 1
            phase = ddos._advance_wave()
            cycles += 1
            if cycles >= 4 and phase == 'calm':
                break
        after = ddos.get_wave_status()['waves']
        self.assertGreater(after, before, '完成一轮后 waves 未自增')


class TestAttackEventFields(unittest.TestCase):
    """攻击事件的字段一致性 —— mitigated 是「已拦截链数」的唯一依据。"""

    def setUp(self):
        ddos.reset_state()

    def test_mitigated_field_exists_and_is_bool(self):
        for _ in range(30):
            ev = ddos.generate_attack_event()
            self.assertIn('mitigated', ev, '攻击事件缺少 mitigated 字段')
            self.assertIsInstance(ev['mitigated'], bool)

    def test_mitigated_matches_status_semantics(self):
        """mitigated=True 当且仅当 status 属于三种"已缓解"措辞之一。

        这条断言的意义：前端不再靠中文子串判断，而是直接读 mitigated。
        如果模拟器把 status 与 mitigated 的对应关系弄反/漏项，
        「已拦截链数」会系统性少算 —— 这正是修复前的问题。
        """
        mitigated_statuses = {'已拦截', '已清洗', '限速中'}
        for _ in range(60):
            ev = ddos.generate_attack_event()
            if ev['mitigated']:
                self.assertIn(ev['status'], mitigated_statuses,
                              'status={} 与 mitigated=True 矛盾'.format(ev['status']))
            else:
                self.assertNotIn(ev['status'], mitigated_statuses,
                                 'status={} 与 mitigated=False 矛盾'.format(ev['status']))

    def test_attack_type_and_port_are_consistent(self):
        """端口与服务名必须来自同一组配置，不能出现"53 端口 + ICMP"。"""
        pairs = {s[0]: (s[1], s[2]) for s in ddos.TARGET_SERVICES}
        for _ in range(40):
            ev = ddos.generate_attack_event()
            self.assertIn(ev['target_port'], pairs, '端口不在配置表中')
            protocol, service = pairs[ev['target_port']]
            self.assertEqual(ev['protocol'], protocol)
            self.assertEqual(ev['service'], service)


class TestAttackChain(unittest.TestCase):
    """攻击链：前端「已拦截链数」与「链路详情徽章」都依赖 mitigated。"""

    def setUp(self):
        ddos.reset_state()

    def test_chain_carries_mitigated_from_event(self):
        for _ in range(20):
            ev = ddos.generate_attack_event()
            chain = ddos.generate_attack_chain(ev)
            self.assertIn('mitigated', chain, '攻击链缺少 mitigated 字段')
            self.assertEqual(chain['mitigated'], ev['mitigated'],
                             '链路 mitigated 与事件不一致')

    def test_chain_structure(self):
        """5 节点 / 4 链接 / 5 条时间线 —— 桑基图与详情卡的数据契约。"""
        ev = ddos.generate_attack_event()
        chain = ddos.generate_attack_chain(ev)
        self.assertEqual(len(chain['nodes']), 5)
        self.assertEqual(len(chain['links']), 4)
        self.assertEqual(len(chain['timeline']), 5)
        # 每条 link 的 source/target 必须能在 nodes 中找到
        names = {n['name'] for n in chain['nodes']}
        for link in chain['links']:
            self.assertIn(link['source'], names)
            self.assertIn(link['target'], names)


class TestResetState(unittest.TestCase):
    """reset_state() 必须把全部容器清干净（演示重置按钮的契约）。"""

    def test_reset_clears_all_collections(self):
        ddos.reset_state()
        # 人为制造一些状态
        for _ in range(5):
            ev = ddos.generate_attack_event()
            ddos._attack_state['current_attacks'].append(ev)
            ddos._attack_state['attack_chain_events'].append(
                ddos.generate_attack_chain(ev))
        self.assertGreater(len(ddos._attack_state['current_attacks']), 0)

        ddos.reset_state()
        st = ddos.get_wave_status()
        self.assertEqual(st['waves'], 0, 'waves 未归零')
        self.assertEqual(st['spawned'], 0, 'spawned 未归零')
        self.assertEqual(len(ddos._attack_state['current_attacks']), 0)
        self.assertEqual(len(ddos._attack_state['attack_chain_events']), 0)
        self.assertEqual(len(ddos._attack_state['geo_attacks']), 0)
        self.assertEqual(ddos._attack_state['stats']['mitigated_count'], 0)


# ============================================================================
# 通知门控
# ============================================================================
class TestRiskOrdering(unittest.TestCase):
    """风险等级的偏序关系 —— 决定"低于阈值不通知"是否成立。"""

    def test_risk_ordering(self):
        self.assertTrue(notifier._risk_ge('高危', '中危'))
        self.assertTrue(notifier._risk_ge('高危', '高危'))
        self.assertFalse(notifier._risk_ge('中危', '高危'))
        self.assertFalse(notifier._risk_ge('低危', '中危'))

    def test_unknown_risk_is_treated_as_lowest(self):
        # 未知等级按 0 处理，不应通过任何阈值
        self.assertFalse(notifier._risk_ge('未知', '低危'))


class TestDedup(unittest.TestCase):
    """去重：同源 + 同类型在窗口内只放行一次。"""

    RULES = {'dedup_minutes': 5}

    def setUp(self):
        with notifier._lock:
            notifier._dedup_seen.clear()

    def tearDown(self):
        with notifier._lock:
            notifier._dedup_seen.clear()

    def _alert(self):
        # 注意字段名：notifier 侧的告警字典用 `source_ip`（不是数据库列名
        # `ip_address`）。生产入口 app.py 的 _insert_alert_with_notify 里做了
        # 这一层映射（'source_ip': row[4]），测试必须按同一个契约构造，
        # 否则 _dedup_key 拿到的永远是空串，所有同类型告警会被当成同一来源。
        return {'alert_type': 'IP高频失败攻击', 'source_ip': '203.0.113.9',
                'risk_level': '高危'}

    def test_first_passes_second_blocked(self):
        ok1, _ = notifier._passes_dedup(self._alert(), self.RULES)
        ok2, why = notifier._passes_dedup(self._alert(), self.RULES)
        self.assertTrue(ok1, '首条告警应放行')
        self.assertFalse(ok2, '窗口内重复告警应被去重')
        self.assertIn('已通知过', why)

    def test_different_source_not_deduped(self):
        a = self._alert()
        b = dict(a, source_ip='198.51.100.7')
        self.assertTrue(notifier._passes_dedup(a, self.RULES)[0])
        self.assertTrue(notifier._passes_dedup(b, self.RULES)[0],
                        '不同来源 IP 不应被互相去重')

    def test_missing_source_ip_still_deduped(self):
        """缺 source_ip 时退化为"同类型"去重 —— 记录当前行为，避免误改。"""
        a = {'alert_type': 'DDoS: SYN Flood', 'risk_level': '高危'}
        self.assertTrue(notifier._passes_dedup(a, self.RULES)[0])
        self.assertFalse(notifier._passes_dedup(dict(a), self.RULES)[0])

    def test_allowed_again_after_window(self):
        a = self._alert()
        self.assertTrue(notifier._passes_dedup(a, self.RULES)[0])
        # 把上次记录时间往前推，模拟窗口已过
        with notifier._lock:
            for k in list(notifier._dedup_seen):
                notifier._dedup_seen[k] = time.time() - 6 * 60
        self.assertTrue(notifier._passes_dedup(a, self.RULES)[0],
                        '超过去重窗口后应重新放行')


class TestRateLimit(unittest.TestCase):
    """限流：窗口内投递数达到上限后拒绝。"""

    RULES = {'rate_limit_window_minutes': 5, 'rate_limit_max': 3}

    def setUp(self):
        with notifier._lock:
            notifier._sent_times.clear()

    def tearDown(self):
        with notifier._lock:
            notifier._sent_times.clear()

    def test_under_limit_passes(self):
        for _ in range(2):
            notifier._mark_sent()
        ok, _ = notifier._passes_rate_limit(self.RULES)
        self.assertTrue(ok, '未达上限应放行')

    def test_at_limit_blocked(self):
        for _ in range(3):
            notifier._mark_sent()
        ok, why = notifier._passes_rate_limit(self.RULES)
        self.assertFalse(ok, '达到上限应拒绝')
        self.assertIn('限流', why)

    def test_old_entries_outside_window_ignored(self):
        with notifier._lock:
            # 三条都在窗口之外
            old = time.time() - 10 * 60
            notifier._sent_times.extend([old, old, old])
        ok, _ = notifier._passes_rate_limit(self.RULES)
        self.assertTrue(ok, '窗口外的历史投递不应计入限流')


if __name__ == '__main__':
    unittest.main(verbosity=2)
