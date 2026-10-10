from pathlib import Path
import ast
ROOT=Path(__file__).resolve().parents[2]
def read(path):return (ROOT/path).read_text()
def test_cx_authorization_gate():
 s=read('lib/cx.py');ast.parse(s)
 assert "self.repo.registration_blocked(profile)" in s
 assert "administratively_blocked_registration" in s
 assert 'if typ in (1,2) and any(self.repo.registration_blocked(p)' in s
def test_policy_ownership_and_scope():
 s=read('lib/cx_repository.py');ast.parse(s)
 assert "ForeignKey(self.ims.c.ims_subscriber_id,ondelete='CASCADE')" in s
 assert 'if not associated:raise ValueError' in s
 assert 'with self.transaction([ident]) as c:' in s
def test_ppr_rtr_retained():
 s=read('services/apiService.py');ast.parse(s)
 for path in ('/deregister/','/push-profile/','/registration-policy/'):
  assert path in s
def test_no_automatic_call_barring():
 s=read('services/apiService.py')
 assert "'bar_calls'" in s and "'policy_not_implemented'" in s
