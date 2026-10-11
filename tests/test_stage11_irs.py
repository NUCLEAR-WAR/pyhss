import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent/'pyhss-devel'/'lib'))
from cx_repository import CxRepository

def test_irs_assignment_isolation():
    state={'groups':{'a':{'state':'registered','registered':['a@x'],'pending':[]},'b':{'state':'registered','registered':['b@x'],'pending':[]}},'scscf':None}
    CxRepository.assign_group(state,'a','scscf-a','realm','peer-a')
    CxRepository.assign_group(state,'b','scscf-b','realm','peer-b')
    assert CxRepository.assigned_server(state,'a')=='scscf-a'
    assert CxRepository.assigned_server(state,'b')=='scscf-b'
    CxRepository.release_group(state,'a')
    assert CxRepository.assigned_server(state,'a') is None
    assert CxRepository.assigned_server(state,'b')=='scscf-b'
