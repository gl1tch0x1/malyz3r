"""Opt-in real-browser workflow test: python tests/browser_assurance.py --channel chrome."""

import argparse
import json
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from malware_scanner.web import Workspace, make_server
from malware_scanner.workbench import run_job


def main():
    from playwright.sync_api import expect, sync_playwright

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channel", default="chrome")
    parser.add_argument("--screenshot", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        rules = root / "rules"
        rules.mkdir()
        source = rules / "detect.yar"
        source.write_text('rule detect { strings: $a="TARGET" condition: $a }')
        samples = []
        for i in range(52):
            positive = i % 2 == 0
            (root / f"sample-{i}").write_text(("TARGET" if positive else "BENIGN") + str(i))
            samples.append(
                dict(
                    path=f"sample-{i}",
                    label="target" if positive else "benign",
                    expected_rules=["detect.yar:detect"] if positive else [],
                    family="Synthetic target" if positive else "Benign controls",
                    provenance="Permitted synthetic browser test",
                    split="development",
                )
            )
        manifest = root / "manifest.json"
        manifest.write_text(
            json.dumps(dict(name="Browser fixture", kind="synthetic", samples=samples))
        )
        workspace = Workspace(
            root,
            catalog={"datasets": {"fixture": "manifest.json"}, "rule_packs": {"test": "rules"}},
        )
        server, token = make_server(workspace, 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(channel=args.channel, headless=True)
                page = browser.new_page(viewport={"width": 1440, "height": 1000})
                errors = []
                page.on("pageerror", lambda e: errors.append(str(e)))
                page.goto(f"http://127.0.0.1:{server.server_port}/#token={token}")
                expect(page.get_by_text("No evaluations yet.", exact=False)).to_be_visible()
                page.get_by_role("button", name="Open evaluations", exact=True).click()
                page.get_by_role("button", name="Run evaluation", exact=True).click()
                expect(page.locator("#notice")).to_contain_text(
                    "Evaluation completed", timeout=30000
                )
                baseline = workspace.history()[0]["run_id"]
                source.write_text(
                    'rule detect { strings: $a="TARGET" $b="BENIGN" condition: any of them }'
                )
                state = run_job(manifest, rules, workspace.runs)
                assert state["status"] == "completed"
                candidate = state["run_id"]
                page.get_by_role("button", name="Refresh history").click()
                expect(page.locator("#candidate option")).to_have_count(3)
                page.locator("#baseline").select_option(baseline)
                page.locator("#candidate").select_option(candidate)
                page.get_by_role("button", name="Release comparison", exact=True).click()
                policy_box = page.get_by_label("Release policy JSON")
                policy_text = policy_box.input_value()
                policy_box.fill('{"version":"1","misspelled_threshold":0}')
                page.get_by_role("button", name="Compare and evaluate policy").click()
                expect(page.locator("#notice")).to_contain_text("Invalid request")
                policy_box.fill(policy_text)
                from malware_scanner.assurance import gate

                gate(
                    workspace.report(baseline),
                    workspace.report(candidate),
                    {"version": "1", "min_recall": 0.9, "require_provenance": True},
                )
                page.get_by_role("button", name="Compare and evaluate policy").click()
                expect(page.locator("#results > p").first).to_have_text("fail")
                expect(page.locator("#notice")).to_have_text("")
                page.get_by_label("Transition filter").select_option("new_false_positive")
                expect(page.get_by_text("26 transitions", exact=False)).to_be_visible()
                with page.expect_download() as download:
                    page.get_by_role("button", name="Export comparison JSON").click()
                exported = json.loads(Path(download.value.path()).read_text())
                assert exported["candidate"]["fp"] == 26
                if args.screenshot:
                    args.screenshot.parent.mkdir(parents=True, exist_ok=True)
                    page.screenshot(path=str(args.screenshot), full_page=True)
                page.get_by_role("button", name="Inspect", exact=True).first.click()
                expect(page.get_by_role("heading", name="Sample evidence")).to_be_visible()
                expect(page.locator(".table-wrap").last.locator("tbody tr")).to_have_count(1)
                expect(page.get_by_role("heading", name="Sample investigation")).to_be_visible()
                with page.expect_download() as sample_download:
                    page.get_by_role("button", name="Export sample report", exact=True).click()
                sample_export = json.loads(Path(sample_download.value.path()).read_text())
                assert sample_export["sample"]["label"] == "benign"
                if args.screenshot:
                    page.screenshot(
                        path=str(args.screenshot.with_name("sample-investigation.png")),
                        full_page=True,
                    )
                page.get_by_role("button", name="Sample evidence", exact=True).click()
                expect(page.locator("tbody tr")).to_have_count(50)
                page.get_by_role("button", name="Next", exact=True).click()
                expect(page.locator("tbody tr")).to_have_count(2)
                page.get_by_label("Search", exact=True).fill("does-not-exist")
                page.get_by_role("button", name="Apply filters").click()
                expect(page.locator("tbody tr")).to_have_count(0)
                expect(page.get_by_text("0–0 of 0", exact=True)).to_be_visible()
                page.get_by_role("button", name="Coverage matrix", exact=True).click()
                expect(page.locator("tbody tr")).to_have_count(2)
                page.get_by_role("button", name="Open evidence for", exact=False).first.click()
                expect(page.locator("tbody tr")).to_have_count(26)
                page.get_by_role("button", name="Rule pack", exact=True).click()
                expect(page.locator("tbody tr")).to_have_count(1)
                page.get_by_role("button", name="Quality overview", exact=True).click()
                expect(page.locator(".metric-card")).to_have_count(6)
                expect(page.locator(".composition-legend button")).to_have_count(5)
                page.get_by_role("button", name="Compact view", exact=True).click()
                expect(page.locator(".compact-view")).to_have_count(1)
                page.get_by_role("button", name="Compact view", exact=True).click()
                page.get_by_role("button", name="False positives 26", exact=True).click()
                expect(page.locator("tbody tr")).to_have_count(26)
                page.get_by_role("button", name="Quality overview", exact=True).click()
                expect(page.locator(".metric-card")).to_have_count(6)
                if args.screenshot:
                    page.screenshot(
                        path=str(args.screenshot.with_name("quality-dashboard.png")), full_page=True
                    )
                page.locator(".metric-card").filter(has_text="False positives").click()
                expect(page.locator("tbody tr")).to_have_count(26)
                page.get_by_role("button", name="Detection map", exact=True).click()
                expect(page.locator("svg.detection-svg")).to_be_visible()
                page.locator(".map-node.family").first.click()
                expect(page.get_by_role("button", name="Inspect family samples")).to_be_visible()
                if args.screenshot:
                    page.screenshot(
                        path=str(args.screenshot.with_name("detection-map.png")), full_page=True
                    )
                expect(page.locator(".map-key span")).to_have_count(4)
                page.get_by_role("button", name="Clear selection", exact=True).click()
                expect(page.locator(".map-node.selected")).to_have_count(0)
                page.get_by_label("Show indicator nodes").uncheck()
                expect(page.locator(".map-node.indicator")).to_have_count(0)
                page.get_by_role("button", name="Fit graph", exact=True).click()
                page.get_by_role("button", name="Show all labels", exact=True).click()
                expect(
                    page.get_by_role("button", name="Show all labels", exact=True)
                ).to_have_attribute("aria-pressed", "true")
                page.get_by_role("button", name="Expand map", exact=True).click()
                expect(page.locator(".expanded-map")).to_have_count(1)
                page.get_by_role("button", name="Restore map", exact=True).click()
                page.get_by_role("button", name="Rule workbench", exact=True).click()
                code = page.get_by_label("YARA rule source")
                expect(code).to_contain_text("")
                code.fill("x" * 12001)
                page.get_by_role("button", name="Validate syntax", exact=True).click()
                expect(page.get_by_role("heading", name="Submission failed")).to_be_visible()
                code.fill("rule broken { condition: }")
                page.get_by_role("button", name="Validate syntax", exact=True).click()
                expect(page.get_by_role("heading", name="Syntax rejected")).to_be_visible(
                    timeout=30000
                )
                imported = 'rule detect {\n    strings:\n        $a = "TARGET"\n    condition:\n        $a\n}'
                page.get_by_label("Import rule text").set_input_files(
                    dict(name="candidate.yar", mimeType="text/plain", buffer=imported.encode())
                )
                expect(code).to_have_value(imported)
                page.get_by_label("Editor font size").select_option("16")
                expect(code).to_have_css("font-size", "16px")
                with page.expect_download() as downloaded:
                    page.get_by_role("button", name="Download draft", exact=True).click()
                assert Path(downloaded.value.path()).read_text() == imported
                expect(page.locator(".line-gutter")).to_have_text("1\n2\n3\n4\n5\n6")
                page.get_by_role("button", name="Validate syntax", exact=True).click()
                expect(page.get_by_role("heading", name="Syntax valid")).to_be_visible(
                    timeout=30000
                )
                if args.screenshot:
                    page.screenshot(
                        path=str(args.screenshot.with_name("rule-workbench.png")), full_page=True
                    )
                page.get_by_role("button", name="Evaluate draft", exact=True).click()
                expect(page.get_by_role("heading", name="Evaluation completed")).to_be_visible(
                    timeout=30000
                )
                assert (
                    source.read_text()
                    == 'rule detect { strings: $a="TARGET" $b="BENIGN" condition: any of them }'
                )
                page.get_by_role("button", name="Operations", exact=True).click()
                expect(page.get_by_role("heading", name="Operational status")).to_be_visible()
                page.set_viewport_size({"width": 390, "height": 844})
                expect(page.get_by_role("heading", name="Operational status")).to_be_visible()
                for view, ready in [
                    ("Quality overview", ".metric-card"),
                    ("Detection map", ".detection-svg"),
                    ("Rule workbench", ".code-editor"),
                ]:
                    page.get_by_role("button", name=view, exact=True).click()
                    expect(page.locator(ready).first).to_be_visible()
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), view
                    if args.screenshot:
                        page.screenshot(
                            path=str(
                                args.screenshot.with_name(
                                    view.lower().replace(" ", "-") + "-mobile.png"
                                )
                            ),
                            full_page=True,
                        )
                page.emulate_media(reduced_motion="reduce")
                expect(page.locator("#content > div")).to_have_css("animation-name", "none")
                page.evaluate("sessionStorage.clear()")
                page.reload()
                expect(page.locator("#notice")).to_contain_text("Authorization required")
                assert not errors, errors
                browser.close()
                print(
                    "Browser workflow passed: real evaluation, comparison, gate, export, evidence, paging, coverage, rules, graph and operations."
                )
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
