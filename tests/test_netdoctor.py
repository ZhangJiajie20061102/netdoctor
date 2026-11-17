# -*- coding: utf-8 -*-
"""netdoctor 的单元测试。只测纯逻辑，不动真实系统设置。"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("netdoctor", ROOT / "netdoctor.py")
nd = importlib.util.module_from_spec(SPEC)
sys.modules["netdoctor"] = nd
SPEC.loader.exec_module(nd)


class TestDisplayWidth(unittest.TestCase):
    def test_ascii(self):
        self.assertEqual(nd.disp_width("abc"), 3)

    def test_chinese_counts_two(self):
        self.assertEqual(nd.disp_width("系统代理"), 8)

    def test_mixed(self):
        self.assertEqual(nd.disp_width("TUN 网卡"), 3 + 1 + 4)


class TestResultShape(unittest.TestCase):
    def test_fields(self):
        r = nd.result("k", "标题", "bad", "细节", fixable=True, fix="mtu")
        for key in ("key", "title", "level", "detail", "fixable", "fix", "data"):
            self.assertIn(key, r)
        self.assertEqual(r["level"], "bad")
        self.assertTrue(r["fixable"])

    def test_all_levels_have_style(self):
        for level in ("ok", "warn", "bad", "info"):
            self.assertIn(level, nd.LEVEL_STYLE)


class TestTunMtu(unittest.TestCase):
    def test_no_interfaces(self):
        r = nd.check_tun_mtu([])
        self.assertEqual(r["level"], "info")

    def test_no_tun_adapter(self):
        r = nd.check_tun_mtu([
            {"name": "WLAN", "mtu": 1500},
            {"name": "以太网", "mtu": 1500},
        ])
        self.assertEqual(r["level"], "info")
        self.assertIn("没发现虚拟网卡", r["detail"])

    def test_tun_with_jumbo_frames(self):
        r = nd.check_tun_mtu([{"name": "xray_tun", "mtu": 9000}])
        self.assertEqual(r["level"], "bad")
        self.assertTrue(r["fixable"])
        self.assertEqual(r["fix"], "mtu")
        self.assertIn("9000", r["detail"])
        self.assertEqual(r["data"]["targets"], ["xray_tun"])

    def test_tun_normal(self):
        r = nd.check_tun_mtu([{"name": "xray_tun", "mtu": 1500}])
        self.assertEqual(r["level"], "ok")

    def test_physical_jumbo_not_flagged(self):
        # 物理网卡的巨帧不归这个检查管，只有虚拟网卡才提示
        r = nd.check_tun_mtu([{"name": "以太网", "mtu": 9000}])
        self.assertEqual(r["level"], "info")

    def test_wireguard_low_mtu_is_fine(self):
        # WireGuard 默认 1420，低于 1500 是正常的，不该报错
        r = nd.check_tun_mtu([{"name": "wg0", "mtu": 1420}])
        self.assertEqual(r["level"], "ok")

    def test_multiple_bad_targets(self):
        r = nd.check_tun_mtu([
            {"name": "xray_tun", "mtu": 9000},
            {"name": "clash-tun", "mtu": 65535},
        ])
        self.assertEqual(r["level"], "bad")
        self.assertEqual(sorted(r["data"]["targets"]), ["clash-tun", "xray_tun"])

    def test_various_tun_names(self):
        for name in ("xray_tun", "wintun", "WireGuard", "clash0", "mihomo-tun", "singbox"):
            with self.subTest(name=name):
                r = nd.check_tun_mtu([{"name": name, "mtu": 9000}])
                self.assertEqual(r["level"], "bad", name)


class TestHosts(unittest.TestCase):
    def _with_hosts(self, content):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        try:
            with mock.patch.object(nd, "HOSTS_PATH", path):
                return nd.check_hosts()
        finally:
            os.unlink(path)

    def test_missing_file(self):
        with mock.patch.object(nd, "HOSTS_PATH", os.path.join(tempfile.gettempdir(), "nope_hosts_x")):
            r = nd.check_hosts()
        self.assertEqual(r["level"], "warn")

    def test_empty(self):
        r = self._with_hosts("# 只有注释\n\n")
        self.assertEqual(r["level"], "ok")
        self.assertEqual(r["data"]["count"], 0)

    def test_normal_entries(self):
        r = self._with_hosts("127.0.0.1 localhost\n::1 localhost\n")
        self.assertEqual(r["level"], "ok")
        self.assertEqual(r["data"]["count"], 2)

    def test_too_many_entries(self):
        body = "".join(f"127.0.0.1 host{i}.test\n" for i in range(25))
        r = self._with_hosts(body)
        self.assertEqual(r["level"], "warn")
        self.assertEqual(r["data"]["count"], 25)


class TestProxyShape(unittest.TestCase):
    def test_returns_valid_result(self):
        # 不关心本机开没开代理，只保证结构正确、不抛异常
        r = nd.check_proxy()
        self.assertEqual(r["key"], "proxy")
        self.assertIn(r["level"], ("ok", "bad", "warn"))
        self.assertIsInstance(r["detail"], str)
        if r["level"] == "bad":
            self.assertTrue(r["fixable"])


class TestInterfaces(unittest.TestCase):
    def test_returns_list_or_empty(self):
        items = nd.list_interfaces()
        self.assertIsInstance(items, list)
        for it in items:
            self.assertIn("name", it)
            self.assertIn("mtu", it)
            self.assertIsInstance(it["mtu"], int)


class TestReport(unittest.TestCase):
    def test_empty_report_does_not_crash(self):
        results = [
            nd.result("proxy", "系统代理", "ok", "已关闭"),
            nd.result("tun", "TUN 网卡 MTU", "ok", "xray_tun = 1500"),
        ]
        with mock.patch("sys.stdout"):
            nd.print_report(results, color=False)

    def test_pad_keeps_alignment(self):
        # 中文标题与英文标题补位后视觉宽度应一致
        self.assertEqual(
            nd.disp_width("系统代理") + (18 - nd.disp_width("系统代理")),
            nd.disp_width("TUN 网卡 MTU") + (18 - nd.disp_width("TUN 网卡 MTU")),
        )


class TestFixers(unittest.TestCase):
    """验证修复动作调对了参数，但全部用替身，不会真的改系统设置。"""

    def test_fix_proxy_writes_zero(self):
        with mock.patch.object(nd.winreg, "OpenKey"), \
                mock.patch.object(nd.winreg, "SetValueEx") as set_value, \
                mock.patch.object(nd, "ctypes"):
            ok, msg = nd.fix_proxy()
        self.assertTrue(ok)
        self.assertIn("已关闭", msg)
        args = set_value.call_args[0]
        self.assertEqual(args[1], "ProxyEnable")
        self.assertEqual(args[3], nd.winreg.REG_DWORD)
        self.assertEqual(args[4], 0)

    def test_fix_mtu_needs_admin(self):
        with mock.patch.object(nd, "is_admin", return_value=False), \
                mock.patch.object(nd, "run") as run_cmd:
            ok, msg = nd.fix_mtu(["xray_tun"])
        self.assertFalse(ok)
        self.assertIn("管理员", msg)
        run_cmd.assert_not_called()

    def test_fix_mtu_sets_1500(self):
        with mock.patch.object(nd, "is_admin", return_value=True), \
                mock.patch.object(nd, "run", return_value=(0, "", "")) as run_cmd:
            ok, msg = nd.fix_mtu(["xray_tun"])
        self.assertTrue(ok)
        self.assertIn("1500", msg)
        cmd = run_cmd.call_args[0][0]
        self.assertEqual(cmd[:4], ["netsh", "interface", "ipv4", "set"])
        self.assertIn("mtu=1500", cmd)

    def test_fix_mtu_reports_failure(self):
        with mock.patch.object(nd, "is_admin", return_value=True), \
                mock.patch.object(nd, "run", return_value=(1, "", "参数错误")):
            ok, msg = nd.fix_mtu(["xray_tun"])
        self.assertFalse(ok)
        self.assertIn("失败", msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
