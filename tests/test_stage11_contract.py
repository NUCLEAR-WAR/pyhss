"""Stage 11 source-level regression guards. Run: pytest -q tests/test_stage11_contract.py"""
from pathlib import Path
import ast
import os

ROOT = Path(os.environ.get('PYHSS_SOURCE_ROOT', Path(__file__).resolve().parents[2]))
SOURCE = ROOT / 'lib' / 'cx_repository.py'

def source():
    return SOURCE.read_text(encoding='utf-8')

def test_repository_parses():
    ast.parse(source())

def test_identity_relationship_validation_exists():
    s = source()
    assert "Duplicate/empty private identities" in s
    assert "Invalid provisioned identity association" in s
    assert "Implicitly registered identities must have consistent private associations" in s

def test_registration_state_scope_requires_migration():
    s = source()
    assert "Table('ims_cx_state'" in s
    # Known Stage 11 gap: subscriber-level S-CSCF, not per-IRS assignment.
    assert "Column('scscf',String(512))" in s

def test_effective_userdata_selects_set():
    s = source()
    assert "x['set_id']==set_id" in s
    assert 'self.live_ifc.c.set_id==set_id' in s
