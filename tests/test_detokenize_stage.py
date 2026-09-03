# """tests/test_detokenize_stage.py — transform/apply.py 의 detokenize_stage 테스트."""

# from unittest.mock import patch

# from app.models import AnalysisContext, Turn
# from app.transform.apply import detokenize_stage


# def make_output_ctx(text: str, role: str | None = "agent_l1") -> AnalysisContext:
#     return AnalysisContext(
#         session_id="sess_1",
#         direction="output",
#         provider="gateway",
#         role=role,
#         turns=[Turn(role="assistant", text=text)],
#     )


# def test_detokenize_stage_calls_vault_with_ctx_fields():
#     ctx = make_output_ctx("카드번호는 <PII:CARD:1> 입니다")
#     with patch(
#         "app.transform.apply.vault.detokenize_text",
#         return_value="카드번호는 4111-1111-1111-1111 입니다",
#     ) as mock_dt:
#         detokenize_stage(ctx)
#     mock_dt.assert_called_once_with("sess_1", "카드번호는 <PII:CARD:1> 입니다", "agent_l1", None)
#     assert ctx.turns[0].text == "카드번호는 4111-1111-1111-1111 입니다"


# def test_detokenize_stage_skips_input_direction():
#     ctx = AnalysisContext(
#         session_id="sess_1",
#         direction="input",
#         provider="gateway",
#         role="agent_l1",
#         turns=[Turn(role="user", text="<PII:CARD:1>")],
#     )
#     with patch("app.transform.apply.vault.detokenize_text") as mock_dt:
#         detokenize_stage(ctx)
#     mock_dt.assert_not_called()
#     assert ctx.turns[0].text == "<PII:CARD:1>"  # input 은 건드리지 않음


# def test_detokenize_stage_empty_turns_noop():
#     ctx = AnalysisContext(
#         session_id="sess_1", direction="output", provider="gateway", role=None, turns=[]
#     )
#     with patch("app.transform.apply.vault.detokenize_text") as mock_dt:
#         detokenize_stage(ctx)
#     mock_dt.assert_not_called()


# def test_detokenize_stage_leaves_unauthorized_tokens_as_is():
#     """vault.detokenize_text 가 scope 실패로 라벨을 그대로 두면, stage 도 그대로 반영."""
#     text = "카드번호는 <PII:CARD:1> 입니다"
#     ctx = make_output_ctx(text, role="unauthorized_role")
#     with patch("app.transform.apply.vault.detokenize_text", return_value=text) as mock_dt:
#         detokenize_stage(ctx)
#     mock_dt.assert_called_once()
#     assert ctx.turns[0].text == text  # 안 바뀜 — 인가 실패 시 fail-closed
