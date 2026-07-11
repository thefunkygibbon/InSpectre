import unittest
from datetime import datetime, timezone

from presence_guard import is_locked_secondary_sighting, apply_secondary_ip_sighting


class DummyDevice:
    def __init__(self):
        self.scan_results = {}
        self.is_online = False
        self.status_changed_at = datetime(2026, 1, 1, tzinfo=timezone.utc)


class LockedSecondaryPresenceTests(unittest.TestCase):
    def test_locked_secondary_sighting_does_not_touch_presence_fields(self):
        dev = DummyDevice()
        baseline_online = dev.is_online
        baseline_changed = dev.status_changed_at

        for i in range(5):
            now = datetime(2026, 1, 1, 0, i + 1, tzinfo=timezone.utc)
            self.assertTrue(is_locked_secondary_sighting(True, "192.168.0.2", "192.168.0.6"))
            dev.scan_results = apply_secondary_ip_sighting(dev.scan_results, "192.168.0.6", "sniffer", now.isoformat())
            self.assertEqual(dev.is_online, baseline_online)
            self.assertEqual(dev.status_changed_at, baseline_changed)

        sec = dev.scan_results.get("secondary_ips_seen", {})
        row = sec.get("192.168.0.6")
        self.assertIsNotNone(row)
        self.assertEqual(row.get("count"), 5)
        self.assertEqual(row.get("source"), "sniffer")


if __name__ == "__main__":
    unittest.main()
