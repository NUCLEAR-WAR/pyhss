import ast
from pathlib import Path
src = Path(__file__).resolve().parents[1] / "lib" / "cx.py"
text = src.read_text()
module = ast.parse(text)
mar = next(node for cls in module.body if isinstance(cls, ast.ClassDef) for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "mar")
segment = ast.get_source_segment(text, mar)
assert "digest_username=canonical" in segment
assert "self.avp(1,digest_username if scheme=='SIP Digest' else private)" in segment
assert "f'{digest_username}:{realm}:{secret}'" in segment
assert "if private!=canonical:" in segment
assert "digest_bootstrap_requires_fixed_voice" in segment
print("Cx MAR canonical-identity static checks passed")
