import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from wifi_scout.diagnostics import diagnose


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.sysfs = self.root / 'sys'
        (self.sysfs / 'class/net').mkdir(parents=True)
        (self.sysfs / 'module').mkdir()
        self.status = self.root / 'status'
        self.status.write_text('Name:\tDO_NOT_EXPORT_PROCESS_NAME\nCapEff:\t0000000000000000\n')

    def tearDown(self):
        self.temporary.cleanup()

    def interface(self, name, *, wireless=False, driver=None, virtual=False, type_number=1):
        if driver:
            device = self.sysfs / 'devices' / ('virtual' if virtual else 'pci0000:00') / name
            interface = device / 'net' / name
            interface.mkdir(parents=True)
            (interface / 'device').symlink_to(device)
            driver_path = self.sysfs / 'bus/pci/drivers' / driver
            driver_path.mkdir(parents=True, exist_ok=True)
            (device / 'driver').symlink_to(driver_path)
            (self.sysfs / 'class/net' / name).symlink_to(interface)
        else:
            interface = self.sysfs / 'class/net' / name
            interface.mkdir()
        (interface / 'type').write_text(str(type_number))
        if wireless:
            (interface / 'phy80211').mkdir()
        # These private fields must never be read or included in the report.
        (interface / 'address').write_text('aa:bb:cc:dd:ee:ff')
        (interface / 'ssid').write_text('PRIVATE_TEST_NETWORK')
        return interface

    def run_diagnostic(self):
        return diagnose(sysfs_root=self.sysfs, proc_status=self.status)

    @patch('wifi_scout.diagnostics.sys.platform', 'linux')
    @patch('wifi_scout.diagnostics.shutil.which', return_value=None)
    @patch('wifi_scout.diagnostics.subprocess.run')
    def test_missing_tools_and_no_radios_are_explicit_without_executing_commands(self, run, _which):
        self.interface('eth0')
        self.interface('lo', type_number=772)
        result = self.run_diagnostic()
        run.assert_not_called()
        self.assertFalse(result['wireless_available'])
        self.assertFalse(result['physical_wireless_available'])
        self.assertFalse(result['virtual_radio']['module_loaded'])
        self.assertEqual(result['virtual_radio']['effective_capabilities'], {'net_admin': False, 'sys_module': False})
        self.assertTrue(all(tool['status'] == 'missing' for tool in result['tools'].values()))
        self.assertIn('physical_wireless_interface', [check['id'] for check in result['checks']])
        for interface in result['interfaces']:
            self.assertEqual(set(interface), {'name', 'wireless', 'type', 'driver', 'monitor'})
        serialized = json.dumps(result)
        for secret in ('aa:bb:cc:dd:ee:ff', 'PRIVATE_TEST_NETWORK', 'DO_NOT_EXPORT_PROCESS_NAME'):
            self.assertNotIn(secret, serialized)

    @patch('wifi_scout.diagnostics.sys.platform', 'linux')
    @patch('wifi_scout.diagnostics.shutil.which', return_value=None)
    def test_physical_driver_and_radiotap_interface_are_reported_without_permission_claim(self, _which):
        self.interface('wlan0', wireless=True, driver='iwlwifi')
        self.interface('wlan1mon', wireless=True, driver='ath9k_htc', type_number=803)
        result = self.run_diagnostic()
        self.assertTrue(result['wireless_available'])
        self.assertTrue(result['physical_wireless_available'])
        self.assertEqual(result['interfaces'][0]['driver'], 'iwlwifi')
        self.assertTrue(result['interfaces'][1]['monitor'])
        self.assertFalse(result['virtual_radio']['effective_capabilities']['net_admin'])
        self.assertIn('live capture permissions', ' '.join(result['limitations']))

    @patch('wifi_scout.diagnostics.sys.platform', 'linux')
    @patch('wifi_scout.diagnostics.shutil.which', return_value=None)
    def test_hwsim_interface_never_counts_as_physical_radio(self, _which):
        self.interface('wlan0', wireless=True, driver='mac80211_hwsim', virtual=True)
        (self.sysfs / 'module/mac80211_hwsim').mkdir(parents=True)
        self.status.write_text('CapEff:\t0000000000011000\n')
        result = self.run_diagnostic()
        self.assertTrue(result['wireless_available'])
        self.assertFalse(result['physical_wireless_available'])
        self.assertTrue(result['virtual_radio']['module_loaded'])
        self.assertEqual(result['virtual_radio']['effective_capabilities'], {'net_admin': True, 'sys_module': True})
        # Missing management tools still prevent an overall readiness claim.
        self.assertTrue(any('does not set these up' in step for step in result['next_steps']))

    @patch('wifi_scout.diagnostics.sys.platform', 'linux')
    @patch('wifi_scout.diagnostics.shutil.which', return_value=None)
    def test_unclassified_wireless_device_is_unknown_not_physical(self, _which):
        self.interface('wlan0', wireless=True)
        result = self.run_diagnostic()
        self.assertTrue(result['wireless_available'])
        self.assertIsNone(result['physical_wireless_available'])
        check = next(check for check in result['checks'] if check['id'] == 'physical_wireless_interface')
        self.assertEqual(check['status'], 'unknown')

    @patch('wifi_scout.diagnostics.sys.platform', 'linux')
    @patch('wifi_scout.diagnostics.shutil.which', return_value=None)
    def test_unavailable_sysfs_or_capability_data_stays_unknown(self, _which):
        result = diagnose(sysfs_root=self.root / 'unavailable', proc_status=self.root / 'missing-status')
        self.assertIsNone(result['wireless_available'])
        self.assertIsNone(result['physical_wireless_available'])
        self.assertIsNone(result['virtual_radio']['module_loaded'])
        self.assertEqual(result['virtual_radio']['effective_capabilities'], {'net_admin': None, 'sys_module': None})

    @patch('wifi_scout.diagnostics.sys.platform', 'darwin')
    @patch('wifi_scout.diagnostics.shutil.which', return_value=None)
    def test_unsupported_platform_does_not_infer_linux_capabilities(self, _which):
        self.interface('wlan0', wireless=True, driver='iwlwifi')
        result = self.run_diagnostic()
        self.assertEqual(result['interfaces'], [])
        self.assertIsNone(result['physical_wireless_available'])
        self.assertIsNone(result['virtual_radio']['module_loaded'])
        self.assertTrue(any('not implemented' in check['summary'] for check in result['checks']))

    @patch('wifi_scout.diagnostics.sys.platform', 'linux')
    @patch('wifi_scout.diagnostics.shutil.which', side_effect=lambda name: '/tools/' + name)
    @patch('wifi_scout.diagnostics.subprocess.run')
    def test_only_bounded_version_commands_run_and_unneeded_output_is_dropped(self, run, _which):
        run.side_effect = lambda args, **kwargs: subprocess.CompletedProcess(args, 0, 'Version 1.2\x1b[2J\nDO_NOT_EXPORT_SECOND_LINE', '')
        result = self.run_diagnostic()
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ['/tools/nmcli', '--version'], ['/tools/tshark', '--version'], ['/tools/iw', '--version'],
        ])
        for call in run.call_args_list:
            self.assertEqual(call.kwargs['timeout'], 5)
            self.assertNotIn('shell', call.kwargs)
        self.assertEqual(result['tools']['tshark']['version'], 'Version 1.2\\u001b[2J')
        self.assertEqual(result['tools']['hostapd']['version_status'], 'not_checked')
        self.assertNotIn('DO_NOT_EXPORT_SECOND_LINE', json.dumps(result))

    @patch('wifi_scout.diagnostics.sys.platform', 'linux')
    @patch('wifi_scout.diagnostics.shutil.which', side_effect=lambda name: '/tools/tshark' if name == 'tshark' else None)
    @patch('wifi_scout.diagnostics.subprocess.run', side_effect=subprocess.TimeoutExpired(['tshark', '--version'], 5))
    def test_failed_version_is_unknown_not_missing_or_working(self, _run, _which):
        result = self.run_diagnostic()
        self.assertEqual(result['tools']['tshark']['status'], 'unknown')
        self.assertEqual(result['tools']['tshark']['version_status'], 'failed')
        self.assertIsNone(result['tools']['tshark']['version'])


if __name__ == '__main__':
    unittest.main()
