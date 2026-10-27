"""Critic send-back, escalation, confidence bands, budget, and Zetaris failure."""

from __future__ import annotations

import threading

from sibyl.agents.critic import CaseView, CriticResult, Side, review
from sibyl.agents.prioritiser import prioritise
from sibyl.agents.reporter import to_markdown
from sibyl.config import load_settings
from sibyl.llm import Completion, Receipt
from sibyl.orchestrator.log import RunLog
from sibyl.orchestrator.run import Bundle, Clock, run_triage

VALIDATOR = "case:internal-admin:pkg:npm/validator@13.7.0:CVE-2025-56200"
AXIOS = "case:internal-admin:pkg:npm/axios@0.21.4:CVE-2023-45857"
APPEND = "case:internal-admin:pkg:npm/append-field@1.0.0:CVE-2026-77078"
MULTER = "case:internal-admin:pkg:npm/multer@1.4.2:CVE-2026-77078"
NVD_TEXT = (
    "A URL validation bypass vulnerability exists in validator.js through version 13.15.15."
)


class Lane:
    def __init__(self, last_affected: str = "13.15.15"):
        self.last_affected = last_affected
        self.calls: list[str] = []
        self._lock = threading.Lock()

    def complete(self, lane, messages, schema):
        with self._lock:
            self.calls.append(lane)
        name = schema.__name__
        if name == "ExtractedRange":
            payload = {
                "quote": "through version 13.15.15",
                "applies_to_package": True,
                "introduced": "0",
                "fixed": None,
                "last_affected": self.last_affected,
                "raw_range": None,
            }
        elif name == "Rationale":
            payload = {"rationale": "The score is 999 because the model said so."}
        elif name == "QuoteJudgement":
            payload = {"supported": True, "reason": "the quote does not make this package affected"}
        else:
            raise AssertionError(name)
        return Completion(
            output=schema.model_validate(payload),
            receipt=Receipt(
                lane=lane,
                requested_model="requested",
                routed_model="routed",
                receipt_id="rcpt-test",
                tokens=2,
                latency_ms=1,
                rerouted=True,
            ),
            repaired=False,
            fell_back=False,
            lane=lane,
        )


def test_validator_is_sent_back_once_and_stays_affected():
    log = RunLog(load_settings())
    try:
        report = run_triage([_validator()], llm=Lane(), log=log)
        events = log.events()
    finally:
        log.delete()
    assert report.state == "DONE"
    assert [card.verdict for card in report.ranked] == ["affected"]
    assert report.ranked[0].record_ids
    assert report.ranked[0].conflicts == []
    assert report.ranked[0].score != 999
    assert any(event["type"] == "recheck" for event in events)
    revision = next(event for event in events if event["type"] == "revision")
    assert revision["payload"]["quote"] == "through version 13.15.15"
    assert not any(event["type"] == "escalation" for event in events)


def test_critic_off_keeps_the_matcher_verdict_with_no_send_back():
    settings = load_settings().model_copy(update={"critic_enabled": False})
    lane = Lane()
    log = RunLog(settings)
    try:
        report = run_triage([_validator()], settings=settings, llm=lane, log=log)
        events = log.events()
    finally:
        log.delete()
    assert report.state == "DONE"
    assert not any(event["type"] in {"recheck", "revision", "escalation"} for event in events)
    assert "deep" not in lane.calls
    [card] = report.ranked
    assert card.verdict == "affected"
    assert card.conflicts, "the NVD disagreement stays on the card unresolved"


def test_injected_description_is_quarantined_and_the_rows_decide():
    import json
    from pathlib import Path

    fixture = json.loads(
        (Path(__file__).parent / "fixtures" / "synthetic" / "injected-nvd-description.json").read_text(encoding="utf-8")
    )
    assert "SYNTHETIC" in fixture["_note"]
    case = _validator()
    case.description = fixture["description"]
    lane = Lane()
    log = RunLog(load_settings())
    try:
        report = run_triage([case], llm=lane, log=log)
        events = log.events()
    finally:
        log.delete()
    assert report.state == "DONE"
    assert "deep" not in lane.calls
    assert not any(event["type"] == "revision" for event in events)
    assert any(event["type"] == "quarantine" for event in events)
    [card] = report.ranked + report.closed + report.needs_human
    assert card in report.needs_human
    by_source = {position["source"]: position["verdict"] for position in card.positions}
    assert by_source["osv"] == "affected"
    assert card.verdict != "not_affected"


def test_axios_is_accepted_with_an_informational_conflict():
    log = RunLog(load_settings())
    lane = Lane()
    try:
        report = run_triage([_axios()], llm=lane, log=log)
    finally:
        log.delete()
    assert report.ranked[0].verdict == "affected"
    assert report.ranked[0].conflicts[0]["severity"] == "informational"
    assert report.ranked[0].conflicts[0]["values_by_source"]["nvd"] == "not_affected"
    assert report.ranked[0].conflicts[0]["values_by_source"]["osv"] == "affected"
    assert "deep" not in lane.calls
    assert report.needs_human == []


def test_second_recheck_escalates():
    log = RunLog(load_settings())
    try:
        report = run_triage([_validator()], llm=Lane(last_affected="3.15.15"), log=log)
        events = log.events()
    finally:
        log.delete()
    assert any(event["type"] == "escalation" for event in events)
    assert report.needs_human
    assert "nvd" in report.needs_human[0].question or report.needs_human[0].positions


def test_append_field_is_accepted_under_multer():
    log = RunLog(load_settings())
    try:
        report = run_triage([_append()], llm=Lane(), log=log)
    finally:
        log.delete()
    assert report.needs_human == []
    assert report.closed[0].accepted_under == MULTER
    text = to_markdown(report)
    assert "does not apply to append-field" in text
    assert "not in the needs-human queue" in text


def test_confidence_bands():
    accept = CriticResult(case_id="c", action="accept", reason="ok", round=1, check="accept")
    ranked = prioritise(_band(0.8), accept, llm=None)
    assert ranked.placement == "ranked"
    assert ranked.flagged is False
    assert ranked.rationale_source == "deterministic"
    assert ranked.rationale.startswith("Deterministic rationale")
    high = prioritise(_band(0.5, exploited=True), accept, llm=Lane())
    assert high.placement == "recheck"
    assert high.score == 40
    assert "999" not in str(high.score)
    assert prioritise(_band(0.5, exploited=True), accept, llm=Lane(), extra_check_done=True).placement == "ranked"
    assert prioritise(_band(0.5), accept, llm=None).placement == "ranked"
    low = prioritise(_band(0.4999), accept, llm=None)
    assert low.placement == "needs_human"
    assert low.question
    blocking = accept.model_copy()
    blocked = _band(0.95)
    blocked.conflict_severity = "blocking"
    assert prioritise(blocked, blocking, llm=None).placement == "needs_human"
    closed = prioritise(
        _band(0.48, verdict="not_affected", applies_to_package=False, related_affected=MULTER, method="text_llm"),
        accept.model_copy(update={"accepted_under": MULTER, "reason": "the finding stays with multer"}),
        llm=None,
    )
    assert closed.placement == "closed"
    assert "multer" in closed.rationale
    plain = prioritise(_band(0.95, verdict="not_affected"), accept)
    assert plain.placement == "closed"
    unsure = prioritise(_band(0.95, verdict="uncertain"), accept)
    assert unsure.placement == "needs_human"
    assert unsure.question


def test_model_rationales_cover_needs_human_and_the_top_ten():
    log = RunLog(load_settings())
    lane = Lane()
    cases = [_ranked_axios(index) for index in range(12)]
    cases.append(_append())
    try:
        report = run_triage(cases, llm=lane, log=log)
    finally:
        log.delete()
    assert len(report.ranked) == 12
    assert report.closed
    fast = lane.calls.count("fast")
    assert fast == 10
    model = [card for card in report.ranked if card.rationale_source == "model"]
    deterministic = [card for card in report.ranked if card.rationale_source == "deterministic"]
    assert len(model) == 10
    assert len(deterministic) == 2
    assert all(card.rationale.startswith("Deterministic rationale") for card in deterministic)


def test_budget_exhaustion_is_a_partial_report():
    log = RunLog(load_settings())
    settings = load_settings().model_copy(update={"run_max_seconds": 1})
    try:
        report = run_triage(
            [_validator(), _axios()],
            llm=Lane(),
            log=log,
            settings=settings,
            clock=Clock(seconds=1),
        )
    finally:
        log.delete()
    assert report.state == "DONE"
    assert report.partial is True
    assert report.unprocessed == [VALIDATOR, AXIOS]
    assert report.ranked == []


def test_zetaris_error_fails_the_run():
    log = RunLog(load_settings())
    try:
        report = run_triage(loader=_down, llm=Lane(), log=log)
        assert log.status() == "FAILED"
    finally:
        log.delete()
    assert report.state == "FAILED"


def test_withdrawn_side_is_a_send_back():
    view = _validator_view()
    view.sides = [
        Side(source="osv", verdict="affected", status="active"),
        Side(source="ghsa", verdict="not_affected", status="withdrawn"),
        Side(source="cna", verdict="affected", status="active"),
    ]
    result = review(view, round=1, llm=None)
    assert result.action == "recheck"
    assert result.check == "withdrawn"


def test_fixed_in_is_not_an_upper_bound():
    view = _axios_view()
    view.description = "The crash is fixed in 2.3.0 and the CPE lists 1.5.1."
    view.sides = [
        Side(source="osv", verdict="affected", fixed="1.6.0"),
        Side(source="nvd", verdict="not_affected", introduced="1.5.1", last_affected="1.5.1"),
    ]
    assert review(view, round=1, llm=None).action == "accept"


def test_osv_silence_sends_an_affected_nvd_only_case_to_a_human():
    view = _band(0.5, verdict="uncertain", osv_not_listed=True)
    view.sides = [Side(source="nvd", verdict="affected")]
    affected = review(view, round=1, llm=None)
    assert affected.action == "reject"
    assert affected.check == "osv_silence"
    view.sides = [Side(source="nvd", verdict="not_affected", fixed="2.0.0")]
    view.verdict = "not_affected"
    cleared = review(view, round=1, llm=None)
    assert cleared.action == "accept"
    assert "did not list" in cleared.reason
    placed = prioritise(view, cleared, llm=None)
    assert placed.placement == "closed"
    assert "did not list" in placed.rationale


def test_quote_judgement_is_shown_the_source_text():
    seen: list[str] = []

    class Capture(Lane):
        def complete(self, lane, messages, schema):
            seen.extend(message["content"] for message in messages)
            return super().complete(lane, messages, schema)

    view = _band(0.48, method="text_llm", verdict="affected")
    view.quote = "through version 13.15.15"
    view.description = "A bug through version 13.15.15."
    result = review(view, round=1, llm=Capture())
    assert result.action == "accept"
    assert view.description in "\n".join(seen)
    assert view.quote in "\n".join(seen)


def test_text_only_queue_row_keeps_the_quote_record_and_bound():
    sentence = "decode-uri-component through 0.4.1 is affected"
    bundle = Bundle(
        case_id="case:internal-admin:pkg:npm/decode-uri-component@0.2.0:CVE-2026-45822",
        package="decode-uri-component",
        version="0.2.0",
        vuln_id="CVE-2026-45822",
        ecosystem="npm",
        purl="pkg:npm/decode-uri-component@0.2.0",
        description=sentence,
        quote="through 0.4.1",
        method="text_llm",
        verdict="uncertain",
        record_id="cve_org:CVE-2026-45822",
        text_bound="0.4.1",
        osv_not_listed=True,
        applies_to_package=True,
    )
    log = RunLog(load_settings())
    try:
        report = run_triage([bundle], llm=Lane(), log=log)
    finally:
        log.delete()
    assert report.ranked == []
    assert report.needs_human
    card = report.needs_human[0]
    assert card.question
    cna = next(item for item in card.positions if item["source"] == "cna")
    assert cna["record_id"] == "cve_org:CVE-2026-45822"
    assert cna["quote"] == "through 0.4.1"
    assert cna["bound"] == "0.4.1"
    assert any(item["source"] == "osv" and item["verdict"] == "not_listed" for item in card.positions)


def test_cvss_on_the_bundle_reaches_the_severity_component():
    bundle = _axios()
    bundle.cvss = 8
    bundle.cvss_source = "cna"
    bundle.cvss_version = "3.1"
    bundle.epss_percentile = 0.42
    log = RunLog(load_settings())
    try:
        report = run_triage([bundle], llm=Lane(), log=log)
    finally:
        log.delete()
    card = report.ranked[0]
    assert card.cvss == 8
    assert card.cvss_source == "cna"
    assert card.cvss_version == "3.1"
    assert card.epss_percentile == 0.42
    assert card.score_factors["severity"] == round(15 * 8 / 10, 4)


def test_nvd_description_sends_validator_back_and_not_axios():
    validator = review(_validator_view(), round=1, llm=None)
    assert validator.action == "recheck"
    assert validator.to == "matcher"
    assert "description" in validator.reason
    axios = review(_axios_view(), round=1, llm=None)
    assert axios.action == "accept"


def _down() -> list[Bundle]:
    raise RuntimeError("Zetaris down")


def _validator() -> Bundle:
    return Bundle(
        case_id=VALIDATOR,
        description=NVD_TEXT,
        internet_facing=False,
        criticality=0.4,
        rows=[
            _range("internal-admin", "pkg:npm/validator@13.7.0", "validator", "13.7.0", "osv", "GHSA-9965-vmph-33xx", "CVE-2025-56200", introduced="0", fixed="13.15.20"),
            _range("internal-admin", "pkg:npm/validator@13.7.0", "validator", "13.7.0", "nvd", "CVE-2025-56200", "CVE-2025-56200", last_affected="3.15.15", record_id="nvd:CVE-2025-56200", range_type="NVD_CPE"),
        ],
    )


def _ranked_axios(index: int) -> Bundle:
    service = f"svc{index}"
    base = _axios()
    rows = []
    for row in base.rows:
        copied = dict(row)
        copied["service_id"] = service
        rows.append(copied)
    from sibyl.agents.matcher import case_id_for

    return Bundle(
        case_id=case_id_for(rows[0]),
        description=base.description,
        rows=rows,
        criticality=index / 20,
    )


def _axios() -> Bundle:
    return Bundle(
        case_id=AXIOS,
        description="An issue discovered in Axios 1.5.1 inadvertently reveals a token.",
        rows=[
            _range("internal-admin", "pkg:npm/axios@0.21.4", "axios", "0.21.4", "osv", "GHSA-wf5p-g6vw-rhxx", "CVE-2023-45857", introduced="0", fixed="1.6.0"),
            _range("internal-admin", "pkg:npm/axios@0.21.4", "axios", "0.21.4", "nvd", "CVE-2023-45857", "CVE-2023-45857", introduced="1.5.1", last_affected="1.5.1", record_id="nvd:CVE-2023-45857", range_type="NVD_CPE"),
        ],
    )


def _append() -> Bundle:
    sentence = "which throws inside the append-field dependency and is not caught by multer"
    return Bundle(
        case_id=APPEND,
        package="append-field",
        version="1.0.0",
        vuln_id="CVE-2026-77078",
        ecosystem="npm",
        description=sentence,
        quote=sentence,
        applies_to_package=False,
        method="text_llm",
        related_affected=MULTER,
    )


def _range(service, purl, package, version, source, vuln_id, cve_id, **extra) -> dict[str, str]:
    row = {
        "service_id": service,
        "purl": purl,
        "ecosystem": "npm",
        "package": package,
        "version": version,
        "source": source,
        "vuln_id": vuln_id,
        "cve_id": cve_id,
        "record_id": extra.pop("record_id", f"{source}:{vuln_id}"),
        "record_status": "active",
        "introduced": extra.pop("introduced", ""),
        "fixed": extra.pop("fixed", ""),
        "last_affected": extra.pop("last_affected", ""),
        "raw_range": "",
        "range_type": extra.pop("range_type", "SEMVER"),
    }
    row.update(extra)
    return row


def _band(confidence: float, **extra) -> CaseView:
    values = dict(
        case_id="c",
        package="pkg",
        version="1.0.0",
        ecosystem="npm",
        vuln_id="CVE-1",
        verdict="affected",
        confidence=confidence,
        method="range_eval",
    )
    values.update(extra)
    return CaseView(**values)


def _validator_view() -> CaseView:
    return CaseView(
        case_id=VALIDATOR,
        package="validator",
        version="13.7.0",
        ecosystem="npm",
        vuln_id="CVE-2025-56200",
        verdict="affected",
        confidence=0.95,
        method="range_eval",
        description=NVD_TEXT,
        sides=[
            {"source": "osv", "verdict": "affected", "fixed": "13.15.20"},
            {"source": "nvd", "verdict": "not_affected", "last_affected": "3.15.15"},
        ],
    )


def _axios_view() -> CaseView:
    return CaseView(
        case_id=AXIOS,
        package="axios",
        version="0.21.4",
        ecosystem="npm",
        vuln_id="CVE-2023-45857",
        verdict="affected",
        confidence=0.95,
        method="range_eval",
        description="An issue discovered in Axios 1.5.1 inadvertently reveals a token.",
        sides=[
            {"source": "osv", "verdict": "affected", "fixed": "1.6.0"},
            {"source": "nvd", "verdict": "not_affected", "introduced": "1.5.1", "last_affected": "1.5.1"},
        ],
    )


def test_model_that_does_not_answer_escalates_the_case_not_the_run():
    from sibyl.llm.client import LLMUnavailable

    class Down:
        def complete(self, lane, messages, schema):
            raise LLMUnavailable("deep: HTTP 499 request_aborted")

    log = RunLog(load_settings())
    try:
        report = run_triage([_validator()], llm=Down(), log=log)
        events = log.events()
    finally:
        log.delete()
    assert report.state == "DONE"
    assert any(event["type"] == "revision_failed" for event in events)
    assert [card.case_id for card in report.needs_human + report.ranked] == [VALIDATOR]
