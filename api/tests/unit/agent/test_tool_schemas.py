from vigia.agent.tool_schemas import build_tool_defs


def test_build_tool_defs_includes_reason_property() -> None:
    defs = build_tool_defs(["whois_asn"], include_meta=False)
    assert len(defs) == 1
    params = defs[0]["function"]["parameters"]
    assert "reason" in params["properties"]
    assert "reason" in params["required"]
    assert "resource" in params["properties"]


def test_build_tool_defs_includes_meta_tools() -> None:
    defs = build_tool_defs(["whois_asn"], include_meta=True)
    names = {d["function"]["name"] for d in defs}
    assert names == {"whois_asn", "advance_phase", "deep_dive"}


def test_deep_dive_requires_asset_id_and_reason() -> None:
    defs = build_tool_defs([], include_meta=True)
    deep_dive = next(d for d in defs if d["function"]["name"] == "deep_dive")
    required = deep_dive["function"]["parameters"]["required"]
    assert set(required) == {"asset_id", "reason"}
