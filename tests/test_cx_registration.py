# Copyright 2026 PyHSS contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Real Diameter bytes + native SQLAlchemy DB + real Milenage, no SIP fiction."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import hashlib,json,os,secrets,uuid
from pathlib import Path
import pytest
from sqlalchemy import select,func,text,update,create_engine
from sqlalchemy.engine import make_url
from database import Database,APN,AUC,SUBSCRIBER,IMS_SUBSCRIBER
from diameter import Diameter
from pyhss_config import config
from milenage import Milenage

# Generated synthetic data: no real subscriber, credentials, or deployed realm.
def digits(length):
    return str(secrets.randbelow(9)+1)+''.join(str(secrets.randbelow(10)) for _ in range(length-1))

TEST_MCC=digits(3);TEST_MNC=digits(2)
FIXED_IMSI=TEST_MCC+TEST_MNC+digits(10)
MOBILE_IMSI=TEST_MCC+TEST_MNC+digits(10)
FIXED_MSISDN=digits(11);MOBILE_MSISDN=digits(12)
FIXED_SECRET=secrets.token_urlsafe(18)
MOBILE_KEY=secrets.token_hex(16);MOBILE_OPC=secrets.token_hex(16)
REALM=uuid.uuid4().hex+'.invalid'
IMPI='+'+FIXED_MSISDN+'@'+REALM
IMPU='sip:'+IMPI+';user=phone'
SERVER='sip:scscf.'+REALM
MOBILE_IMPI=MOBILE_IMSI+'@'+REALM
MOBILE_IMPU='sip:'+MOBILE_IMPI

class NullLog:
    def log(self,*args,**kwargs):return True
class NullRedis:
    def sendMetric(self,*args,**kwargs):return True

@pytest.fixture
def lab(tmp_path,monkeypatch):
    test_url=os.getenv('PYHSS_CX_TEST_URL')
    if test_url:
        from database import Base
        url=make_url(test_url)
        if not url.database or not url.database.startswith('pyhss_test_cx'):pytest.fail('Use a disposable pyhss_test_cx* database')
        engine=create_engine(url)
        # Dispose test tables only in the explicitly selected isolated test DB.
        with engine.begin() as c:
            for table in ('ims_cx_identity','ims_cx_state','ims_cx_profile'):c.execute(text(f'DROP TABLE IF EXISTS {table}'))
        Base.metadata.drop_all(engine);engine.dispose()
        monkeypatch.setitem(config,'database',{'db_type':url.get_backend_name(),'database':url.database,
            'server':url.host,'port':url.port,'username':url.username,'password':url.password or ''})
    else:monkeypatch.setitem(config,'database',{'db_type':'sqlite','database':str(tmp_path/'hss.db')})
    monkeypatch.setitem(config['hss'],'MCC',TEST_MCC)
    monkeypatch.setitem(config['hss'],'MNC',TEST_MNC)
    monkeypatch.setitem(config['hss'],'OriginHost','hss.'+REALM)
    monkeypatch.setitem(config['hss'],'OriginRealm',REALM)
    monkeypatch.setitem(config['hss'],'scscf_pool',[])
    monkeypatch.setitem(config['hss'],'cx',{'server_capabilities':{'mandatory':[0],'optional':[1]}})
    db=Database(NullLog(),redisMessaging=NullRedis(),main_service=True)
    apn=db.CreateObj(APN,{'apn':'ims','apn_ambr_ul':1000000,'apn_ambr_dl':1000000},disable_logging=True)
    profiles=[]
    for imsi,msisdn,key,opc in [(FIXED_IMSI,FIXED_MSISDN,FIXED_SECRET,''),
                               (MOBILE_IMSI,MOBILE_MSISDN,MOBILE_KEY,MOBILE_OPC)]:
        auc=db.CreateObj(AUC,{'ki':key,'opc':opc,'amf':'8000','sqn':0,'imsi':imsi},disable_logging=True)
        db.CreateObj(SUBSCRIBER,{'imsi':imsi,'auc_id':auc['auc_id'],'default_apn':apn['apn_id'],'apn_list':str(apn['apn_id']),'msisdn':msisdn,'enabled':True},disable_logging=True)
        ims=db.CreateObj(IMS_SUBSCRIBER,{'imsi':imsi,'msisdn':msisdn,'ifc_path':'default_ifc.xml',
            'scscf':SERVER,'scscf_timestamp':None},disable_logging=True)
        profiles.append((ims,auc))
    d=Diameter(NullLog(),'hss.'+REALM,REALM,'PyHSS test',TEST_MCC,TEST_MNC,redisMessaging=NullRedis())
    repo=d.cx.repo
    repo.provision(profiles[0][0]['ims_subscriber_id'],{
        'private_identities':[IMPI],'public_identities':[
            {'identity':IMPU,'set_id':'voice','barred':False},
            {'identity':'tel:+'+FIXED_MSISDN,'set_id':'voice','barred':False}],
        'authentication_scheme':'SIP Digest','digest_realm':REALM,
        'visited_networks':[REALM],'unregistered_service':False})
    repo.provision(profiles[1][0]['ims_subscriber_id'],{
        'private_identities':[MOBILE_IMPI],'public_identities':[
            {'identity':MOBILE_IMPU,'set_id':'mobile','barred':True},
            {'identity':'sip:+'+MOBILE_MSISDN+'@'+REALM+';user=phone','set_id':'mobile','barred':False}],
        'authentication_scheme':'Digest-AKAv1-MD5','digest_realm':REALM,
        'visited_networks':[REALM]})
    yield d,profiles
    db.engine.dispose();d.database.engine.dispose()

def request(d,command,private=IMPI,public=IMPU,extra='',omit=()):
    cx=d.cx
    avps=''
    values=[(263,'icscf.'+REALM+';'+uuid.uuid4().hex,0,False),(264,'scscf.'+REALM,0,False),
            (296,REALM,0,False),(283,REALM,0,False),(277,1,0,True)]
    for code,value,vendor,integer in values:
        if code not in omit:avps+=cx.avp(code,value,vendor,integer)
    avps+=cx.grouped(260,cx.avp(266,10415,integer=True)+cx.avp(258,16777216,integer=True),vendor=0)
    if private is not None and 1 not in omit:avps+=cx.avp(1,private)
    if public is not None and 601 not in omit:avps+=cx.avp(601,public,10415)
    if command==300 and 600 not in omit:avps+=cx.avp(600,REALM,10415)
    wire=d.generate_diameter_packet('01','c0',command,16777216,'5992ad7b','3db70bec',avps+extra)
    packet,avps=d.decode_diameter_packet(bytes.fromhex(wire))
    answer=getattr(d,f'Answer_16777216_{command}')(packet,avps)
    header,decoded=d.decode_diameter_packet(bytes.fromhex(answer))
    assert header['ApplicationId']==16777216 and header['command_code']==command
    assert header['hop-by-hop-identifier']=='5992ad7b' and header['end-to-end-identifier']=='3db70bec'
    assert len(bytes.fromhex(answer))==header['length']
    return decoded,answer

def result(d,avps):
    base=d.get_avp_data(avps,268);experimental=d.get_avp_data(avps,298)
    assert bool(base)!=bool(experimental),'Never emit both result mechanisms'
    if experimental:
        grouped=d.cx.one(avps,297)
        assert int(d.get_avp_data(grouped['sub_avps'],266)[0],16)==10415
    return ('experimental' if experimental else 'base',int((experimental or base)[0],16))

def mar(d,private=IMPI,public=IMPU,scheme='SIP Digest',count=1,server=SERVER,token=None):
    cx=d.cx;children=cx.avp(608,scheme,10415)
    if token is not None:children+=cx.avp(610,token,10415)
    return request(d,303,private,public,cx.avp(602,server,10415)+cx.avp(607,count,10415,True)+cx.grouped(612,children))

def sar(d,typ,private=IMPI,public=IMPU,available=0,server=SERVER,extra=''):
    cx=d.cx
    return request(d,301,private,public,cx.avp(614,typ,10415,True)+cx.avp(624,available,10415,True)+cx.avp(602,server,10415)+extra)

def snapshot(d,private=IMPI,public=IMPU):
    profile=d.cx.repo.resolve(public,private)
    with d.cx.repo.engine.connect() as c:return d.cx.repo.state(profile,c)

def test_number_impi_maps_to_existing_credentials_and_first_uar_is_read_only(lab):
    d,profiles=lab;repo=d.cx.repo
    with repo.engine.connect() as c:
        before=[c.scalar(select(func.count()).select_from(t)) for t in (repo.profiles,repo.identities,repo.states)]
    avps,_=request(d,300)
    assert result(d,avps)==('experimental',2001)
    assert not d.get_avp_data(avps,602) and d.get_avp_data(avps,603)
    with repo.engine.connect() as c:
        assert before==[c.scalar(select(func.count()).select_from(t)) for t in (repo.profiles,repo.identities,repo.states)]
        assert c.scalar(select(repo.sub.c.imsi).where(repo.sub.c.msisdn==FIXED_MSISDN))==FIXED_IMSI
    avps,wire=mar(d)
    assert result(d,avps)==('base',2001)
    assert d.get_avp_data(avps,635) and not d.get_avp_data(avps,609) and not d.get_avp_data(avps,610)
    expected=hashlib.md5(f'{IMPI}:{REALM}:{FIXED_SECRET}'.encode()).hexdigest()
    assert bytes.fromhex(d.get_avp_data(avps,121)[0]).decode()==expected
    assert FIXED_SECRET.encode() not in bytes.fromhex(wire)
    assert snapshot(d)['groups']['voice']['state']=='not_registered'
    assert snapshot(d)['registered_at'] is None
    avps,_=request(d,300);assert result(d,avps)==('experimental',2002)
    avps,_=sar(d,1);assert result(d,avps)==('base',2001)
    assert snapshot(d)['groups']['voice']['pending']==[] and snapshot(d)['registered_at']
    avps,_=request(d,302,private=None,public='tel:+'+FIXED_MSISDN)
    assert result(d,avps)==('base',2001)

@pytest.mark.parametrize('command',[300,301,303])
def test_unknown_private_identity_never_learns_from_known_public(lab,command):
    d,_=lab
    if command==303:avps,_=mar(d,private='unknown@'+REALM)
    elif command==301:avps,_=sar(d,1,private='unknown@'+REALM)
    else:avps,_=request(d,300,private='unknown@'+REALM)
    assert result(d,avps)==('experimental',5001)
    with d.cx.repo.engine.connect() as c:assert c.scalar(select(func.count()).select_from(d.cx.repo.states))==0

@pytest.mark.parametrize('command',[300,301,303])
def test_known_private_and_wrong_public_returns_identities_dont_match(lab,command):
    d,_=lab
    if command==303:avps,_=mar(d,private=MOBILE_IMPI)
    elif command==301:avps,_=sar(d,1,private=MOBILE_IMPI)
    else:avps,_=request(d,300,private=MOBILE_IMPI)
    assert result(d,avps)==('experimental',5002)

def test_wrong_public_realm_is_not_accepted_by_matching_number(lab):
    d,_=lab;avps,_=request(d,300,public='sip:+'+FIXED_MSISDN+'@evil.invalid')
    assert result(d,avps)==('experimental',5001)

def test_unknown_unassigned_lir_never_returns_random_scscf(lab):
    d,_=lab
    avps,_=request(d,302,private=None);assert result(d,avps)==('experimental',5003)
    assert not d.get_avp_data(avps,602)

def test_capabilities_query_does_not_mutate_existing_assignment(lab):
    d,_=lab;mar(d);sar(d,1);before=snapshot(d)
    avps,_=request(d,300,extra=d.cx.avp(623,2,10415,True))
    assert result(d,avps)==('base',2001) and not d.get_avp_data(avps,602)
    assert snapshot(d)==before

def test_uar_deregistration_is_read_only_until_sar(lab):
    d,_=lab;mar(d);sar(d,1);before=snapshot(d)
    avps,_=request(d,300,extra=d.cx.avp(623,1,10415,True))
    assert result(d,avps)==('base',2001) and snapshot(d)==before
    avps,_=sar(d,5);assert result(d,avps)==('base',2001)
    assert snapshot(d)['scscf'] is None
    avps,_=request(d,300);assert result(d,avps)==('experimental',2001)

@pytest.mark.parametrize('typ',[4,5,8,11])
def test_deregistration_clears_server_without_user_data(lab,typ):
    d,_=lab;mar(d);sar(d,1)
    avps,_=sar(d,typ)
    assert result(d,avps)==('base',2001) and not d.get_avp_data(avps,606)
    assert snapshot(d)['scscf'] is None

@pytest.mark.parametrize('typ',[6,7])
def test_store_server_deregistration_retains_unregistered_state(lab,typ):
    d,_=lab;mar(d);sar(d,1)
    avps,_=sar(d,typ);assert result(d,avps)==('base',2001)
    assert snapshot(d)['groups']['voice']['state']=='unregistered'
    avps,_=request(d,300);assert result(d,avps)==('experimental',2002)

@pytest.mark.parametrize('typ',[9,10])
def test_authentication_failure_clears_only_pending_initial_assignment(lab,typ):
    d,_=lab;mar(d)
    avps,_=sar(d,typ);assert result(d,avps)==('base',2001)
    assert snapshot(d)['scscf'] is None

def test_failed_reauthentication_does_not_erase_existing_registration(lab):
    d,_=lab;mar(d);sar(d,1);mar(d)
    avps,_=sar(d,9);assert result(d,avps)==('base',2001)
    assert snapshot(d)['scscf']==SERVER and snapshot(d)['groups']['voice']['state']=='registered'

def test_no_assignment_does_not_deregister(lab):
    d,_=lab;mar(d);sar(d,1);before=snapshot(d)
    avps,_=sar(d,0);assert result(d,avps)==('base',2001)
    assert snapshot(d)==before

def test_wrong_server_cannot_clear_registration(lab):
    d,_=lab;mar(d);sar(d,1);before=snapshot(d)
    avps,_=sar(d,5,server='sip:other.invalid')
    assert result(d,avps)==('experimental',5005) and snapshot(d)==before
    assert bytes.fromhex(d.get_avp_data(avps,602)[0]).decode()==SERVER

def test_sar_user_data_already_available_and_full_private_identity(lab):
    d,_=lab;mar(d);avps,_=sar(d,1)
    xml=bytes.fromhex(d.get_avp_data(avps,606)[0]).decode()
    assert '<PrivateID>'+IMPI+'</PrivateID>' in xml and IMPU in xml
    import xml.etree.ElementTree as ET
    for sp in ET.fromstring(xml).findall('ServiceProfile'):
        tags=[child.tag for child in sp]
        last_public=max(i for i,t in enumerate(tags) if t=='PublicIdentity')
        assert all(t=='PublicIdentity' for t in tags[:last_public+1])
    avps,_=sar(d,2,available=1)
    assert result(d,avps)==('base',2001) and not d.get_avp_data(avps,606)

def test_aka_auth_vectors_are_real_and_requested_count_is_honored(lab):
    d,profiles=lab
    avps,_=mar(d,MOBILE_IMPI,MOBILE_IMPU,'Digest-AKAv1-MD5',3)
    assert result(d,avps)==('base',2001)
    assert int(d.get_avp_data(avps,607)[0],16)==3 and len(d.cx.values(avps,612,10415))==3
    for item in d.cx.values(avps,612,10415):
        data=bytes.fromhex(d.get_avp_data(item['sub_avps'],609)[0]);assert len(data)==32
        rand,autn=data[:16],data[16:];key=bytes.fromhex(profiles[1][1]['ki']);opc=bytes.fromhex(profiles[1][1]['opc'])
        xres,ak=Milenage.f2_f5(key,rand,opc)
        sqn=bytes(x^y for x,y in zip(autn[:6],ak));mac,_=Milenage.f1(key,sqn,rand,opc,autn[6:8])
        assert mac==autn[8:] and xres==bytes.fromhex(d.get_avp_data(item['sub_avps'],610)[0])
    with d.cx.repo.engine.connect() as c:assert c.scalar(select(d.cx.repo.auc.c.sqn).where(d.cx.repo.auc.c.auc_id==profiles[1][1]['auc_id']))==3

def test_resync_mac_is_verified_before_sqn_changes(lab):
    d,profiles=lab;avps,_=mar(d,MOBILE_IMPI,MOBILE_IMPU,'Digest-AKAv1-MD5')
    rand=bytes.fromhex(d.get_avp_data(avps,609)[0])[:16]
    key=bytes.fromhex(profiles[1][1]['ki']);opc=bytes.fromhex(profiles[1][1]['opc'])
    auts=Milenage(b'\0\0').generate_auts(key,opc,rand,100)
    bad=rand+auts[:-1]+bytes([auts[-1]^1])
    avps,_=mar(d,MOBILE_IMPI,MOBILE_IMPU,'Digest-AKAv1-MD5',token=bad)
    assert result(d,avps)==('base',4001)
    with d.cx.repo.engine.connect() as c:assert c.scalar(select(d.cx.repo.auc.c.sqn).where(d.cx.repo.auc.c.auc_id==profiles[1][1]['auc_id']))==1
    avps,_=mar(d,MOBILE_IMPI,MOBILE_IMPU,'Digest-AKAv1-MD5',token=rand+auts)
    assert result(d,avps)==('base',2001)
    with d.cx.repo.engine.connect() as c:assert c.scalar(select(d.cx.repo.auc.c.sqn).where(d.cx.repo.auc.c.auc_id==profiles[1][1]['auc_id']))==102

def test_legacy_digest_md5_is_explicitly_gated_and_never_returns_password(lab):
    d,_=lab;avps,_=mar(d,scheme='Digest-MD5')
    assert result(d,avps)==('experimental',5006)
    d.cx.settings['accept_legacy_digest_md5']=True
    avps,wire=mar(d,scheme='Digest-MD5')
    assert result(d,avps)==('base',2001)
    assert bytes.fromhex(d.get_avp_data(avps,608)[0]).decode()=='SIP Digest'
    assert d.get_avp_data(avps,635) and FIXED_SECRET.encode() not in bytes.fromhex(wire)

def test_malformed_and_missing_avps_never_mutate_state(lab):
    d,_=lab;avps,_=request(d,300,omit=(1,))
    assert result(d,avps)==('base',5005) and d.get_avp_data(avps,279)
    avps,_=request(d,300,extra=d.cx.avp(1,IMPI))
    assert result(d,avps)==('base',5009)
    avps,_=request(d,300,extra=d.cx.grouped(623,'00000000000000000000000000000001'))
    assert result(d,avps)==('base',5004)

def test_duplicate_public_avps_in_registration_return_base_error_in_cx(lab):
    d,_=lab;avps,_=sar(d,1,extra=d.cx.avp(601,IMPU,10415))
    assert result(d,avps)==('base',5009) and not d.get_avp_data(avps,606)

def test_concurrent_aka_mar_transactions_do_not_reuse_sqn(lab):
    d,profiles=lab
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses=list(pool.map(lambda _:mar(d,MOBILE_IMPI,MOBILE_IMPU,'Digest-AKAv1-MD5'),range(12)))
    assert all(result(d,a)==('base',2001) for a,_ in responses)
    with d.cx.repo.engine.connect() as c:assert c.scalar(select(d.cx.repo.auc.c.sqn).where(d.cx.repo.auc.c.auc_id==profiles[1][1]['auc_id']))==12

def test_identity_user_parts_remain_case_sensitive_on_every_backend(lab):
    d,profiles=lab;repo=d.cx.repo
    with repo.engine.connect() as c:definition=repo.definition(profiles[0][0],c)
    definition['private_identities']=['CaseUser@'+REALM]
    for public in definition['public_identities']:public['private_identities']=definition['private_identities']
    repo.provision(profiles[0][0]['ims_subscriber_id'],definition,replace=True)
    avps,_=request(d,300,private='caseuser@'+REALM)
    assert result(d,avps)==('experimental',5001)
    avps,_=request(d,300,private='CaseUser@'+REALM)
    assert result(d,avps)==('experimental',2001)

def test_unknown_scheme_selects_only_provisioned_standard_sip_digest(lab):
    d,_=lab;avps,_=mar(d,scheme='Unknown')
    assert result(d,avps)==('base',2001) and d.get_avp_data(avps,635)
    avps,_=mar(d,MOBILE_IMPI,MOBILE_IMPU,'Unknown')
    assert result(d,avps)==('experimental',5006)

def test_no_registered_identity_is_created_by_initial_lir_originating_request(lab):
    d,_=lab;avps,_=request(d,302,private=None,extra=d.cx.avp(633,0,10415,True))
    assert result(d,avps)==('experimental',2003) and not d.get_avp_data(avps,602)
    with d.cx.repo.engine.connect() as c:assert c.scalar(select(func.count()).select_from(d.cx.repo.states))==0

def test_store_server_can_be_declined_without_claiming_assignment(lab):
    d,_=lab;mar(d);sar(d,1);d.cx.settings['store_server_on_deregistration']=False
    avps,_=sar(d,7);assert result(d,avps)==('experimental',2004)
    assert snapshot(d)['scscf'] is None

def test_multiple_private_registrations_are_not_erased_by_one_deregistration(lab):
    d,profiles=lab;repo=d.cx.repo;other='second-private@'+REALM
    with repo.engine.connect() as c:definition=repo.definition(profiles[0][0],c)
    definition['private_identities'].append(other)
    for public in definition['public_identities']:public['private_identities']=definition['private_identities']
    repo.provision(profiles[0][0]['ims_subscriber_id'],definition,replace=True)
    mar(d);sar(d,1);mar(d,private=other);sar(d,1,private=other)
    avps,_=sar(d,5)
    assert result(d,avps)==('base',2001)
    assert snapshot(d,private=other)['groups']['voice']['registered']==[other]
    assert snapshot(d,private=other)['scscf']==SERVER

def test_backend_failure_rolls_back_registration_and_credential_changes(lab,monkeypatch):
    d,profiles=lab;repo=d.cx.repo
    original=repo.save
    def fail_after_writes(state,c):
        original(state,c);raise RuntimeError('simulated database failure')
    monkeypatch.setattr(repo,'save',fail_after_writes)
    avps,_=mar(d,MOBILE_IMPI,MOBILE_IMPU,'Digest-AKAv1-MD5')
    assert result(d,avps)==('base',5012)
    with repo.engine.connect() as c:
        assert c.scalar(select(repo.auc.c.sqn).where(repo.auc.c.auc_id==profiles[1][1]['auc_id']))==0
        assert c.scalar(select(func.count()).select_from(repo.states))==0

def test_account_suspension_does_not_prevent_deregistration_query(lab):
    d,_=lab;mar(d);sar(d,1)
    with d.cx.repo.engine.begin() as c:
        c.execute(update(d.cx.repo.sub).where(d.cx.repo.sub.c.msisdn==FIXED_MSISDN).values(enabled=False))
    avps,_=request(d,300);assert result(d,avps)==('base',5003)
    avps,_=request(d,300,extra=d.cx.avp(623,1,10415,True))
    assert result(d,avps)==('base',2001)

def test_native_oam_clear_cannot_leave_a_stale_cx_assignment(lab):
    d,_=lab;mar(d);sar(d,1)
    d.database.Update_Serving_CSCF(imsi=FIXED_IMSI,serving_cscf=None,propagate=False)
    avps,_=request(d,300)
    assert result(d,avps)==('experimental',2001) and not d.get_avp_data(avps,602)
    with d.cx.repo.engine.connect() as c:assert c.scalar(select(func.count()).select_from(d.cx.repo.states))==0

def test_outbound_rtr_uses_actual_impi_and_native_ims_destination(lab,monkeypatch):
    d,_=lab;mar(d);sar(d,1);sent=[]
    monkeypatch.setattr(d,'sendDiameterRequest',lambda **kw:sent.append(kw))
    assert d.deregisterIms(imsi=FIXED_IMSI)
    assert len(sent)==1 and sent[0]['hostname']=='scscf.'+REALM
    assert sent[0]['destinationHost']=='scscf.'+REALM
    packet=d.Request_16777216_304(imsi=FIXED_IMSI,domain=REALM,destinationHost='scscf.'+REALM,destinationRealm=REALM)
    header,avps=d.decode_diameter_packet(bytes.fromhex(packet))
    assert header['ApplicationId']==16777216 and header['command_code']==304
    assert bytes.fromhex(d.get_avp_data(avps,1)[0]).decode()==IMPI
    assert snapshot(d)['scscf'] is None

def test_rtr_names_private_identity_actually_known_to_scscf(lab):
    d,profiles=lab;repo=d.cx.repo;other='registered-alias@'+REALM
    with repo.engine.connect() as c:definition=repo.definition(profiles[0][0],c)
    definition['private_identities'].append(other)
    for public in definition['public_identities']:public['private_identities']=definition['private_identities']
    repo.provision(profiles[0][0]['ims_subscriber_id'],definition,replace=True)
    mar(d,private=other);sar(d,1,private=other)
    packet=d.Request_16777216_304(FIXED_IMSI,REALM,'scscf.'+REALM,REALM)
    _,avps=d.decode_diameter_packet(bytes.fromhex(packet))
    assert bytes.fromhex(d.get_avp_data(avps,1)[0]).decode()==other

def test_saa_xml_validates_with_supplied_ims_schema(lab):
    etree=pytest.importorskip('lxml.etree')
    schema=etree.XMLSchema(etree.parse(str(Path(__file__).parent/'fixtures/CxDataType_Rel8.xsd')))
    d,_=lab
    for private,public,scheme in [(IMPI,IMPU,'SIP Digest'),(MOBILE_IMPI,MOBILE_IMPU,'Digest-AKAv1-MD5')]:
        mar(d,private,public,scheme)
        avps,_=sar(d,1,private,public)
        xml=bytes.fromhex(d.get_avp_data(avps,606)[0])
        assert schema.validate(etree.fromstring(xml)),str(schema.error_log)

def test_first_uar_does_not_invent_operator_capability_numbers(lab):
    d,_=lab;d.cx.settings.pop('server_capabilities')
    avps,_=request(d,300)
    assert result(d,avps)==('experimental',2001)
    assert not d.get_avp_data(avps,602) and not d.get_avp_data(avps,603)

def test_default_diameter_identity_comes_from_operator_config(lab):
    d,_=lab
    other=Diameter(NullLog(),redisMessaging=NullRedis())
    try:
        assert bytes.fromhex(other.OriginHost).decode()==config['hss']['OriginHost']
        assert bytes.fromhex(other.OriginRealm).decode()==config['hss']['OriginRealm']
        assert other.MCC==TEST_MCC and other.MNC==TEST_MNC
    finally:other.database.engine.dispose()

def test_ifc_network_values_come_from_config(lab,tmp_path):
    d,profiles=lab
    template=tmp_path/'operator-ifc.xml'
    template.write_text('<IMSSubscription><PrivateID>{{ iFC_vars.mcc }}:{{ iFC_vars.mnc }}</PrivateID></IMSSubscription>')
    record=dict(profiles[0][0]);record['ifc_path']=str(template)
    assert d.cx.repo.xml(record).findtext('PrivateID')==TEST_MCC+':'+TEST_MNC.zfill(3)

@pytest.mark.parametrize('field',['MCC','MNC'])
def test_missing_plmn_configuration_has_no_fallback(lab,monkeypatch,field):
    d,profiles=lab
    monkeypatch.delitem(config['hss'],field)
    with pytest.raises(ValueError,match='Configure hss.'+field):
        d.cx.repo.xml(profiles[0][0])
    # AKA failure cannot consume SQN or assign an S-CSCF with guessed values.
    avps,_=mar(d,MOBILE_IMPI,MOBILE_IMPU,'Digest-AKAv1-MD5')
    assert result(d,avps)==('base',5012)
    with d.cx.repo.engine.connect() as c:
        assert c.scalar(select(d.cx.repo.auc.c.sqn).where(d.cx.repo.auc.c.auc_id==profiles[1][1]['auc_id']))==0
        assert c.scalar(select(func.count()).select_from(d.cx.repo.states))==0
