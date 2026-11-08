import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import unittest
from main import audit

def row(u, g, priv):
    return {"user": u, "group": g, "privileged": priv}

class TestGroupAudit(unittest.TestCase):
    def test_privileged_group_listed(self):
        groups, _ = audit([row("ali", "Domain Admins", "yes")])
        self.assertEqual(groups, [("Domain Admins", ["ali"])])
    def test_non_privileged_group_skipped(self):
        groups, _ = audit([row("ali", "All Staff", "no")])
        self.assertEqual(groups, [])
    def test_most_members_first(self):
        groups, _ = audit([row("a", "G1", "yes"), row("b", "G1", "yes"), row("c", "G2", "yes")])
        self.assertEqual(groups[0][0], "G1")
    def test_high_exposure_user(self):
        _, multi = audit([row("ali", "Domain Admins", "yes"), row("ali", "Schema Admins", "yes")])
        self.assertEqual(multi, [("ali", ["Domain Admins", "Schema Admins"])])
    def test_single_privileged_group_not_flagged(self):
        _, multi = audit([row("ali", "Domain Admins", "yes")])
        self.assertEqual(multi, [])
