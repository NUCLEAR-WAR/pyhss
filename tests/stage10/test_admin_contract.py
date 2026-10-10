import ast
from pathlib import Path

def test_ui_routes():
 root=Path(__file__).resolve().parents[3]
 p=root/'ims_lab_full-main/pyhss_admin/pyhss_5gc/admin/app.py'
 if not p.exists():
  import pytest
  pytest.skip('Admin UI source not alongside PyHSS test checkout')
 s=p.read_text();ast.parse(s)
 assert 'cx_registration_policy' in s
 assert 'cx_live_ifc' in s and 'cx_deregister' in s
