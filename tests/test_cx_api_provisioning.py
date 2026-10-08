# Copyright 2026 PyHSS contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
from copy import deepcopy
import importlib.util,json,sys,secrets
from pathlib import Path
import pytest
from sqlalchemy import select,func
from cx_provisioning import CxProvisioning,ProvisioningConflict
from database import AUC,SUBSCRIBER,IMS_SUBSCRIBER
from test_cx_registration import lab,REALM,digits,NullLog,NullRedis,mar,sar,result,request
from pyhss_config import config

def bundle(d,mode='sip_digest'):
    imsi=digits(15);number=digits(11)
    with d.database.engine.connect() as c:apn=c.scalar(select(d.cx.repo.sub.c.default_apn).limit(1))
    return {'auc':{'imsi':imsi,'ki':secrets.token_hex(16),'opc':secrets.token_hex(16),'amf':'8000','sqn':0},
        'subscriber':{'imsi':imsi,'msisdn':number,'default_apn':apn,'apn_list':str(apn),'enabled':True},
        'ims_subscriber':{'imsi':imsi,'msisdn':number,'ifc_path':'default_ifc.xml',
            'cx':{'authentication':mode,'realm':REALM,'service_type':'fixed_voice' if mode=='sip_digest' else 'mobile_voice_data'}}}

def totals(d):
    tables=(AUC.__table__,SUBSCRIBER.__table__,IMS_SUBSCRIBER.__table__,d.cx.repo.profiles,d.cx.repo.identities)
    with d.database.engine.connect() as c:return [c.scalar(select(func.count()).select_from(table)) for table in tables]

def test_native_service_and_cx_are_provisioned_atomically_and_digest_bootstrap_is_canonical(lab):
    d,_=lab;svc=CxProvisioning(d.database,config);payload=bundle(d)
    result_data=svc.create_service(payload)
    ims=result_data['ims_subscriber'];profile=ims['cx']
    private=payload['subscriber']['imsi']+'@'+REALM;lookup='+'+payload['subscriber']['msisdn']+'@'+REALM;public='sip:'+lookup
    assert profile['provisioning']['private_identity']==private
    assert profile['digest_identity_aliases'][lookup]==private
    assert 'ki' not in result_data['auc']
    avps,_=request(d,300,private=lookup,public=public);assert result(d,avps)==('experimental',2001)
    avps,_=mar(d,lookup,public,'SIP Digest');assert result(d,avps)==('base',2001)
    assert bytes.fromhex(d.get_avp_data(avps,1)[0]).decode()==private
    assert svc.get(ims['ims_subscriber_id'])['cx']==profile

def test_bad_ifc_rolls_back_auc_subscriber_ims_and_cx(lab):
    d,_=lab;svc=CxProvisioning(d.database,config);payload=bundle(d);before=totals(d)
    payload['ims_subscriber']['ifc_path']='nonexistent-test-ifc.xml'
    with pytest.raises(Exception):svc.create_service(payload)
    assert totals(d)==before

def test_identity_conflict_rolls_back_all_native_rows(lab):
    d,profiles=lab;svc=CxProvisioning(d.database,config);payload=bundle(d)
    with d.database.engine.connect() as c:old=d.cx.repo.definition(profiles[0][0],c)
    payload['ims_subscriber']['cx']={'private_identities':old['private_identities'],
        'public_identities':old['public_identities'],'authentication_scheme':'SIP Digest','digest_realm':REALM}
    before=totals(d)
    with pytest.raises(ValueError,match='another subscription'):svc.create_service(payload)
    assert totals(d)==before

def test_api_update_regenerates_managed_numbers_without_keeping_stale_index(lab):
    d,_=lab;svc=CxProvisioning(d.database,config);payload=bundle(d);saved=svc.create_service(payload)['ims_subscriber']
    previous='sip:+'+payload['subscriber']['msisdn']+'@'+REALM
    replacement=digits(11)
    updated=svc.save({'msisdn':replacement},saved['ims_subscriber_id'])
    assert previous not in [item['identity'] for item in updated['cx']['public_identities']]
    with d.database.engine.connect() as c:assert c.scalar(select(func.count()).select_from(svc.repo.identities).where(svc.repo.identities.c.identity==previous))==0
    svc.remove(saved['ims_subscriber_id'])
    with d.database.engine.connect() as c:
        for table in (svc.repo.identities,svc.repo.profiles,svc.repo.states):
            assert c.scalar(select(func.count()).select_from(table).where(table.c.ims_subscriber_id==saved['ims_subscriber_id']))==0

def test_registered_identity_update_rolls_back_native_msisdn_change(lab):
    d,_=lab;svc=CxProvisioning(d.database,config);payload=bundle(d);saved=svc.create_service(payload)['ims_subscriber']
    private=payload['subscriber']['imsi']+'@'+REALM;public='sip:+'+payload['subscriber']['msisdn']+'@'+REALM
    mar(d,private,public);sar(d,1,private,public)
    with pytest.raises(ProvisioningConflict):svc.save({'msisdn':digits(11)},saved['ims_subscriber_id'])
    assert svc.get(saved['ims_subscriber_id'])['msisdn']==saved['msisdn']

def test_snapshot_uses_native_engine_and_excludes_auc_secrets(lab):
    d,_=lab;snapshot=CxProvisioning(d.database,config).snapshot()
    assert snapshot['auc'] and snapshot['subscriber'] and snapshot['apn']
    assert all('ki' not in item and 'opc' not in item for item in snapshot['auc'])

def test_atomic_update_keeps_native_and_cx_numbers_coherent_and_rolls_back_when_registered(lab):
    d,_=lab;svc=CxProvisioning(d.database,config);saved=svc.create_service(bundle(d))
    sid=saved['subscriber']['subscriber_id'];iid=saved['ims_subscriber']['ims_subscriber_id'];replacement=digits(11)
    updated=svc.update_service(sid,{'subscriber':{'msisdn':replacement},'ims_subscriber':{'msisdn':replacement}})
    assert updated['subscriber']['msisdn']==updated['ims_subscriber']['msisdn']==replacement
    private=updated['ims_subscriber']['cx']['provisioning']['private_identity'];public='sip:+'+replacement+'@'+REALM
    mar(d,private,public);sar(d,1,private,public)
    with pytest.raises(ProvisioningConflict):svc.update_service(sid,{'subscriber':{'msisdn':digits(11)},'ims_subscriber':{'msisdn':digits(11)},'auc':{'ki':'changed'}})
    with d.database.engine.connect() as c:assert c.scalar(select(SUBSCRIBER.msisdn).where(SUBSCRIBER.subscriber_id==sid))==replacement
    assert svc.get(iid)['msisdn']==replacement

def test_barring_from_ifc_and_explicit_profile_survives_api_edits(lab,tmp_path):
    d,_=lab;svc=CxProvisioning(d.database,config);payload=bundle(d,'aka')
    primary=payload['subscriber']['imsi']+'@'+REALM
    template=tmp_path/'barred.xml'
    template.write_text('<IMSSubscription><PrivateID>'+primary+'</PrivateID><ServiceProfile><PublicIdentity><BarringIndication>1</BarringIndication><Identity>sip:'+primary+'</Identity></PublicIdentity><PublicIdentity><Identity>sip:+'+payload['subscriber']['msisdn']+'@'+REALM+'</Identity></PublicIdentity></ServiceProfile></IMSSubscription>')
    payload['ims_subscriber']['ifc_path']=str(template)
    saved=svc.create_service(payload)['ims_subscriber']
    assert next(x for x in saved['cx']['public_identities'] if x['identity']=='sip:'+primary)['barred'] is True
    updated=svc.save({'cx':{'authentication':'aka'}},saved['ims_subscriber_id'])
    assert next(x for x in updated['cx']['public_identities'] if x['identity']=='sip:'+primary)['barred'] is True
    updated=svc.save({'cx':{'bar_private_impu':False}},saved['ims_subscriber_id'])
    assert next(x for x in updated['cx']['public_identities'] if x['identity']=='sip:'+primary)['barred'] is False

def test_standard_ims_crud_routes_automatically_create_update_and_remove_cx(api_client):
    client,module,d=api_client
    payload=bundle(d)['ims_subscriber']
    response=client.put('/ims_subscriber/',json=payload);assert response.status_code==200,response.get_json()
    ident=response.get_json()['ims_subscriber_id']
    assert response.get_json()['cx']['private_identities']
    replacement=digits(11)
    response=client.patch('/ims_subscriber/'+str(ident),json={'msisdn':replacement})
    assert response.status_code==200,response.get_json()
    assert 'sip:+'+replacement+'@'+REALM in [x['identity'] for x in response.get_json()['cx']['public_identities']]
    response=client.delete('/ims_subscriber/'+str(ident));assert response.status_code==200,response.get_json()
    with module.databaseClient.engine.connect() as c:assert not c.scalar(select(module.cxProvisioning.repo.profiles.c.ims_subscriber_id).where(module.cxProvisioning.repo.profiles.c.ims_subscriber_id==ident))

@pytest.fixture
def api_client(lab,monkeypatch):
    import messaging,logtool
    monkeypatch.setattr(messaging,'RedisMessaging',lambda *args,**kwargs:NullRedis())
    monkeypatch.setattr(logtool,'LogTool',lambda cfg:NullLog())
    path=Path(__file__).resolve().parents[1]/'services/apiService.py'
    spec=importlib.util.spec_from_file_location('api_cx_test',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    yield module.apiService.test_client(),module,lab[0]
    module.databaseClient.engine.dispose();module.diameterClient.database.engine.dispose()

def test_real_api_routes_create_ims_and_cx_and_respect_provisioning_key(api_client,monkeypatch):
    client,module,d=api_client;payload=bundle(d)
    response=client.put('/provisioning/subscriber/',json=payload)
    assert response.status_code==200,response.get_json()
    ident=response.get_json()['ims_subscriber']['ims_subscriber_id']
    response=client.get('/ims_subscriber/'+str(ident))
    assert response.status_code==200 and response.get_json()['cx']['digest_identity_aliases']
    monkeypatch.setattr(module,'lockProvisioning',True)
    monkeypatch.setitem(config['hss'],'provisioning_key',secrets.token_hex(16))
    response=client.put('/provisioning/subscriber/',json=bundle(d))
    assert response.status_code==401
