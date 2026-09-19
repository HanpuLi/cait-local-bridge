import unittest
from bridge import semantic_ui


class SemanticUiPureTests(unittest.TestCase):
    def test_fingerprint_stable_ignores_mutable_state(self):
        base = {"role":"AXButton","subrole":"","identifier":"ok","title":"OK","description":""}
        a = dict(base, enabled=True, focused=False, value="one")
        b = dict(base, enabled=False, focused=True, value="two")
        self.assertEqual(semantic_ui.fingerprint_fields(a), semantic_ui.fingerprint_fields(b))

    def test_fingerprint_changes_identity(self):
        a = {"role":"AXButton","subrole":"","identifier":"ok","title":"OK","description":""}
        b = dict(a, title="Cancel")
        self.assertNotEqual(semantic_ui.fingerprint_fields(a), semantic_ui.fingerprint_fields(b))

    def test_fingerprint_includes_rounded_frame(self):
        a = {
            "role":"AXButton","subrole":"","identifier":"ok","title":"OK","description":"",
            "frame":{"x":10.1,"y":20.1,"width":100.1,"height":30.1},
        }
        b = dict(a, frame={"x":11.2,"y":20.1,"width":100.1,"height":30.1})
        c = dict(a, frame={"x":10.2,"y":20.2,"width":100.2,"height":30.2})
        self.assertNotEqual(semantic_ui.fingerprint_fields(a), semantic_ui.fingerprint_fields(b))
        self.assertEqual(semantic_ui.fingerprint_fields(a), semantic_ui.fingerprint_fields(c))

    def test_parse_ref(self):
        self.assertEqual(
            semantic_ui.parse_ref("ax:123:0.2.1:0123456789abcdef"),
            (123, [0, 2, 1], "0123456789abcdef"),
        )
        self.assertEqual(
            semantic_ui.parse_ref("ax:7:root:ffffffffffffffff"),
            (7, [], "ffffffffffffffff"),
        )

    def test_bad_ref(self):
        with self.assertRaises(Exception):
            semantic_ui.parse_ref("ax:x:root:no")

    def test_selector(self):
        fields = {
            "role":"AXButton", "title":"Save document", "description":"primary",
            "enabled":True, "selected":False, "value":"ready",
            "url":"https://example.test/document",
        }
        self.assertTrue(semantic_ui.selector_matches(fields, {"role":"AXButton","title_contains":"save"}))
        self.assertFalse(semantic_ui.selector_matches(fields, {"enabled":False}))
        self.assertTrue(semantic_ui.selector_matches(fields, {"value_contains":"ead"}))
        self.assertTrue(semantic_ui.selector_matches(fields, {"selected":False,"url_contains":"example.test"}))

    def test_state_diff_is_bounded_and_tracks_mutable_state(self):
        before = {
            "same": {
                "ref":"ax:1:0:aaaaaaaaaaaaaaaa",
                "identity":{"role":"AXCheckBox","title":"Wi-Fi"},
                "state":{"enabled":True,"value":"0"},
            },
            "gone": {
                "ref":"ax:1:1:bbbbbbbbbbbbbbbb",
                "identity":{"role":"AXButton","title":"Old"},
                "state":{"enabled":True},
            },
        }
        after = {
            "same": {
                "ref":"ax:1:0:aaaaaaaaaaaaaaaa",
                "identity":{"role":"AXCheckBox","title":"Wi-Fi"},
                "state":{"enabled":True,"value":"1"},
            },
            "new": {
                "ref":"ax:1:2:cccccccccccccccc",
                "identity":{"role":"AXStaticText","title":"Connected"},
                "state":{},
            },
        }
        diff = semantic_ui.diff_state_maps(before, after)
        self.assertEqual(diff["counts"], {"added":1,"removed":1,"changed":1})
        self.assertEqual(diff["changed"][0]["before"]["value"], "0")
        self.assertEqual(diff["changed"][0]["after"]["value"], "1")
        self.assertFalse(diff["truncated"])


if __name__ == "__main__":
    unittest.main()
