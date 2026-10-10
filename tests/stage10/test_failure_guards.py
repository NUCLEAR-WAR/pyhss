from pathlib import Path
import ast
ROOT=Path(__file__).resolve().parents[2]
def test_rtr_does_not_clear_without_rta():
 s=(ROOT/'services/apiService.py').read_text();ast.parse(s)
 assert "if safe['rta_confirmed']:" in s
 assert 'expected_rtr_state' in s
 assert 'reconcile_rtr' in s
def test_ppr_version_audit():
 s=(ROOT/'services/apiService.py').read_text()
 assert 'ppr_finish' in s and 'profile_version' in s
 assert 'ppa_confirmed' in s
def test_no_default_scscf():
 s=(ROOT/'services/apiService.py').read_text()
 assert "scscf = state.get('scscf')" in s
 assert 'destination_host = urlsplit' in s
