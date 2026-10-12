import sys,copy
from contextlib import contextmanager
sys.path.insert(0,'/mnt/data/rtr_fix_work/pyhss-devel/lib')
from cx_rtr_reconcile import reconcile_rtr
class Repo:
 def __init__(self,groups):
  self.value={'ims_subscriber_id':7,'scscf':'sip:scscf.example','realm':'example','peer':'peer','registered_at':'time','groups':copy.deepcopy(groups)}
 @contextmanager
 def transaction(self,ids):yield None
 def record(self,id,c):return {'ims_subscriber_id':id}
 def definition(self,record,c):return {}
 def state(self,profile,c):return copy.deepcopy(self.value)
 def save(self,state,c):self.value=copy.deepcopy(state)

def check():
 a={'state':'registered','registered':['a'],'pending':[]}
 b={'state':'registered','registered':['b'],'pending':[]}
 repo=Repo({'A':a,'B':b});before=copy.deepcopy(repo.value)
 r=reconcile_rtr(repo,7,'A','a',0,before)
 assert r['hss_state_reconciled'] and repo.value['groups']['B']==b
 assert repo.value['groups']['A']['registered']==[]
 assert repo.value['scscf'] is not None
 before=copy.deepcopy(repo.value)
 r=reconcile_rtr(repo,7,'B','b',2,before)
 assert r['hss_state_reconciled'] and repo.value['scscf'] is None and repo.value['registered_at'] is None
 repo=Repo({'A':a});before=copy.deepcopy(repo.value);repo.value['groups']['A']['registered'].append('other')
 assert reconcile_rtr(repo,7,'A','a',0,before)['reconciliation_status']=='state_changed'
 repo=Repo({'A':{'state':'unregistered','registered':[],'pending':[]}})
 assert reconcile_rtr(repo,7,'A','a',3,copy.deepcopy(repo.value))['hss_state_reconciled']
 repo=Repo({'A':a})
 assert reconcile_rtr(repo,7,'A','a',1,copy.deepcopy(repo.value))['reconciliation_status']=='external_reassignment_required'
 print('5 scoped RTR reconciliation scenarios PASS')
check()
