"""Stage 11: source integration contracts, no DB or network mutation."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def test_outbound_routing_is_irs_scoped():
    api=(ROOT/'services/apiService.py').read_text()
    assert "selected_group = groups[selected_set]" in api
    assert "selected_group = eligible[selected_set]" in api
    assert "peer = selected_group.get('peer')" in api
    assert "scscf = selected_group.get('scscf')" in api
    assert "realm = selected_group.get('realm')" in api

def test_reconciliation_only_releases_selected_group():
    src=(ROOT/'lib/cx_rtr_reconcile.py').read_text()
    assert 'repo.release_group(current, registration_set)' in src
    assert "current['scscf'] = None" not in src
    assert "actual_group != expected_group" in src

def test_cx_routing_is_irs_scoped():
    src=(ROOT/'lib/cx.py').read_text()
    assert 'self.repo.assigned_server(state,' in src
    assert 'self.repo.assign_group(state,' in src
    assert 'self.repo.release_group(state,' in src
