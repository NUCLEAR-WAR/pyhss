"""Guard the shared Redis namespace used by API and DiameterService."""
from pathlib import Path
import ast


def test_diameter_uses_configured_origin_host_for_redis_namespace():
    source = Path(__file__).resolve().parents[1] / "lib" / "diameter.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Diameter")
    init = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "__init__")
    assignments = [n for n in ast.walk(init) if isinstance(n, ast.Assign) and
                   any(isinstance(t, ast.Attribute) and t.attr == "hostname" and
                       isinstance(t.value, ast.Name) and t.value.id == "self"
                       for t in n.targets)]
    assert len(assignments) == 1
    assert "originHost" in ast.unparse(assignments[0].value)
    assert "gethostname" not in ast.unparse(assignments[0].value)


def test_outbound_rtr_resolves_only_assigned_scscf():
    source = Path(__file__).resolve().parents[1] / "lib" / "cx_outbound_peer.py"
    text = source.read_text(encoding="utf-8")
    assert "diameter.getPeerByHostname(hostname=target)" in text
    assert "peer_ambiguous" in text
    assert "_host(p.get('hostname')) == target" in text
