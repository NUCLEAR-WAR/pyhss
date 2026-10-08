# SPDX-License-Identifier: AGPL-3.0-or-later
from copy import deepcopy
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import pytest
from sqlalchemy import select,update
from cx_repository import CxRepository
from cx_provisioning import CxProvisioning,ProvisioningConflict
from pyhss_config import config
from test_cx_registration import lab,REALM,SERVER,digits,request,result,mar,sar,snapshot
from test_cx_api_provisioning import bundle,api_client
from test_cx_admin_provisioning import ui_client
from test_cx_diagnostics import diagnostics

def xml(trigger='',part=None):
    return '<IMSSubscription><PrivateID>test@'+REALM+'</PrivateID><ServiceProfile><PublicIdentity><Identity>sip:test@'+REALM+'</Identity></PublicIdentity><InitialFilterCriteria><Priority>10</Priority>'+('<ProfilePartIndicator>'+part+'</ProfilePartIndicator>' if part else '')+trigger+'<ApplicationServer><ServerName>sip:as.'+REALM+'</ServerName><DefaultHandling>0</DefaultHandling></ApplicationServer></InitialFilterCriteria></ServiceProfile></IMSSubscription>'

def trigger(method='INVITE',session='2',cnf='0',session_group='0',negate='0'):
    return '<TriggerPoint><ConditionTypeCNF>'+cnf+'</ConditionTypeCNF><SPT><Group>0</Group><Method>'+method+'</Method></SPT><SPT><ConditionNegated>'+negate+'</ConditionNegated><Group>'+session_group+'</Group><SessionCase>'+session+'</SessionCase></SPT></TriggerPoint>'

def setup(d,tmp_path,policy=None):
    svc=CxProvisioning(d.database,config);payload=bundle(d)
    path=tmp_path/'active-ifc.xml';path.write_text(xml(trigger()))
    payload['ims_subscriber']['ifc_path']=str(path)
    if policy:payload['ims_subscriber']['cx'].update(policy)
    ims=svc.create_service(payload)['ims_subscriber'];private=ims['cx']['provisioning']['private_identity']
    public=next(x['identity'] for x in ims['cx']['public_identities'] if x['identity'].startswith('sip:+'))
    return svc,ims,private,public,path

def data(repo):
    with repo.engine.connect() as c:return {t.name:list(c.execute(select(t))) for t in (repo.profiles,repo.identities,repo.states,repo.ims,repo.auc)}

@pytest.mark.parametrize('expression,part,expected',[
    (trigger(),None,True),(trigger(session='1'),None,False),
    (trigger(method='REGISTER'),None,False),(trigger(negate='1'),None,False),
    (trigger(), '0',False),(trigger(), '1',True),('',None,True),
    (trigger(cnf='1',session_group='1'),None,True),
    (trigger(cnf='1',session_group='1',session='1'),None,False),
    (trigger(cnf='1',session_group='0',session='1'),None,True),
])
def test_ifc_service_detection_respects_boolean_groups_and_profile_part(expression,part,expected):
    assert CxRepository.ifc_has_terminating_unregistered_service(ET.fromstring(xml(expression,part))) is expected

def test_auto_policy_unassigned_lir_returns_2003_candidates_without_assignment_then_sar3(lab,tmp_path):
    d,_=lab;svc,ims,private,public,path=setup(d,tmp_path)
    d.cx.repo.config['hss']['scscf_pool']=[SERVER]
    assert ims['cx']['unregistered_service_policy']=='auto' and ims['cx']['unregistered_service']
    before=data(svc.repo)
    avps,_=request(d,302,private=None,public=public)
    assert result(d,avps)==('experimental',2003)
    assert not d.cx.values(avps,602,10415)
    caps=d.cx.one(avps,603,10415)
    assert [bytes.fromhex(a['misc_data']).decode() for a in d.cx.values(caps['sub_avps'],602,10415)]==[SERVER]
    assert data(svc.repo)==before
    avps,_=sar(d,3,private=None,public=public);assert result(d,avps)==('base',2001)
    assert bytes.fromhex(d.get_avp_data(avps,1)[0]).decode()==private
    root=ET.fromstring(bytes.fromhex(d.get_avp_data(avps,606)[0]))
    assert root.findtext('.//SessionCase')=='2'
    avps,_=request(d,302,private=None,public=public);assert result(d,avps)==('base',2001)
    assert not d.cx.values(avps,603,10415)
    state=snapshot(d,private,public)
    assert state['groups']['fixed']['state']=='unregistered' and state['registered_at'] is None

def test_legacy_generated_false_follows_actual_ifc_without_db_rewrite(lab,tmp_path):
    d,_=lab;svc,ims,private,public,path=setup(d,tmp_path);ident=ims['ims_subscriber_id']
    old=deepcopy(ims['cx']);old.pop('unregistered_service_policy');old['unregistered_service']=False
    with svc.repo.engine.begin() as c:c.execute(update(svc.repo.profiles).where(svc.repo.profiles.c.ims_subscriber_id==ident).values(definition=json.dumps(old)))
    before=data(svc.repo)
    avps,_=request(d,302,private=None,public=public);assert result(d,avps)==('experimental',2003)
    assert data(svc.repo)==before
    report=diagnostics.diagnose(svc.repo.engine,public=public)
    assert report['unregistered_service_policy']=='auto' and report['unregistered_service_effective']
    assert report['assigned_scscf'] is None

def test_auto_reloads_ifc_and_explicit_overrides_are_authoritative(lab,tmp_path):
    d,_=lab;svc,ims,private,public,path=setup(d,tmp_path);ident=ims['ims_subscriber_id']
    path.write_text(xml(trigger(session='1')))
    avps,_=request(d,302,private=None,public=public);assert result(d,avps)==('experimental',5003)
    svc.save({'cx':{'unregistered_service_policy':'enabled'}},ident)
    avps,_=request(d,302,private=None,public=public);assert result(d,avps)==('experimental',2003)
    path.write_text(xml(trigger()))
    svc.save({'cx':{'unregistered_service_policy':'disabled'}},ident)
    avps,_=request(d,302,private=None,public=public);assert result(d,avps)==('experimental',5003)
    avps,_=request(d,302,private=None,public=public,extra=d.cx.avp(633,0,10415,True))
    assert result(d,avps)==('experimental',2003)
    avps,_=request(d,302,private=None,public=public,extra=d.cx.avp(633,1,10415,True))
    assert result(d,avps)==('base',5004)

def test_manual_explicit_false_profile_is_not_silently_enabled(lab,tmp_path):
    d,_=lab;svc,ims,private,public,path=setup(d,tmp_path);ident=ims['ims_subscriber_id']
    old=deepcopy(ims['cx']);old.pop('provisioning');old.pop('unregistered_service_policy');old['unregistered_service']=False
    svc.repo.provision(ident,old,replace=True)
    avps,_=request(d,302,private=None,public=public);assert result(d,avps)==('experimental',5003)

def test_registered_routing_and_registration_fix_remain_unchanged_during_policy_edit(lab,tmp_path):
    d,_=lab;svc,ims,private,public,path=setup(d,tmp_path);ident=ims['ims_subscriber_id']
    lookup=public[4:];mar(d,lookup,public);sar(d,1,private,public)
    before=data(svc.repo)
    svc.save({'cx':{'unregistered_service_policy':'disabled'}},ident);after=data(svc.repo)
    for table in ('ims_cx_state','ims_cx_identity','auc'):assert before[table]==after[table]
    avps,_=request(d,302,private=None,public=public);assert result(d,avps)==('base',2001)
    assert bytes.fromhex(d.get_avp_data(avps,602)[0]).decode()==SERVER
    avps,_=request(d,300,lookup,public);assert result(d,avps)==('experimental',2002)
    with pytest.raises(ProvisioningConflict):svc.save({'msisdn':digits(11),'cx':{'unregistered_service_policy':'auto'}},ident)

def test_unknown_identity_does_not_gain_service_from_default_ifc(lab,tmp_path):
    d,_=lab;setup(d,tmp_path)
    avps,_=request(d,302,private=None,public='sip:unknown-'+digits(5)+'@'+REALM)
    assert result(d,avps)==('experimental',5001)
    assert not d.cx.values(avps,603,10415)

def test_policy_only_edit_through_admin_keeps_registered_state(ui_client,tmp_path):
    client,ui,module,d=ui_client
    svc,ims,private,public,path=setup(d,tmp_path);ident=ims['ims_subscriber_id']
    mar(d,public[4:],public);sar(d,1,private,public);before=snapshot(d,private,public)
    response=client.get('/ims/'+str(ident)+'/edit')
    assert 'cx_unregistered_service_policy' in response.text and 'Follow installed IFC' in response.text
    response=client.post('/ims/'+str(ident)+'/edit',{'cx_unregistered_service_policy':'disabled'})
    assert response.status_code==303,response.text
    assert svc.get(ident)['cx']['unregistered_service_policy']=='disabled'
    assert snapshot(d,private,public)==before
