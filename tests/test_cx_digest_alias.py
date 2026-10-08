# Copyright 2026 PyHSS contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
import sys
import pytest
from sqlalchemy import select,func
from cx_repository import CxRepository
from test_cx_registration import lab,REALM,MOBILE_IMPI,MOBILE_IMPU,digits,request,result,mar,sar,snapshot
from test_cx_associations import tool_module
from test_cx_registration import NullLog

def configure(d,record):
    repo=d.cx.repo;alias='+'+digits(11)+'@'+REALM;public='sip:'+alias+';user=phone'
    with repo.engine.connect() as c:base=repo.definition(record,c)
    extra={'private_identities':[MOBILE_IMPI,alias],
        'public_identities':[{'identity':public,'set_id':'fixed','barred':False}],
        'authentication_scheme':'SIP Digest','digest_realm':REALM,'visited_networks':[REALM],
        'digest_identity_aliases':{alias:MOBILE_IMPI}}
    definition=tool_module().preserve_definition(base,extra,allow_additional_scheme=True)
    repo.provision(record['ims_subscriber_id'],definition,replace=True)
    return alias,public,definition

def test_initial_digest_maa_returns_actual_authentication_impi_and_matching_ha1(lab):
    d,profiles=lab;repo=d.cx.repo;alias,public,_=configure(d,profiles[1][0])
    avps,_=request(d,300,private=alias,public=public)
    assert result(d,avps)==('experimental',2001)
    avps,_=mar(d,alias,public,'SIP Digest',count=3)
    assert result(d,avps)==('base',2001)
    assert bytes.fromhex(d.get_avp_data(avps,1)[0]).decode()==MOBILE_IMPI
    expected=hashlib.md5(f'{MOBILE_IMPI}:{REALM}:{profiles[1][1]["ki"]}'.encode()).hexdigest()
    alias_ha1=hashlib.md5(f'{alias}:{REALM}:{profiles[1][1]["ki"]}'.encode()).hexdigest()
    assert bytes.fromhex(d.get_avp_data(avps,121)[0]).decode()==expected and expected!=alias_ha1
    assert int(d.get_avp_data(avps,607)[0],16)==1
    assert len(d.cx.values(avps,612,10415))==1 and not d.get_avp_data(avps,613)
    state=snapshot(d,MOBILE_IMPI,public)
    assert state['groups']['fixed']['pending']==[MOBILE_IMPI] and state['registered_at'] is None
    avps,_=sar(d,1,private=MOBILE_IMPI,public=public)
    assert result(d,avps)==('base',2001)
    assert snapshot(d,MOBILE_IMPI,public)['groups']['fixed']['pending']==[]
    avps,_=sar(d,5,private=MOBILE_IMPI,public=public)
    assert result(d,avps)==('base',2001)
    state=snapshot(d,MOBILE_IMPI,public)
    assert state['scscf'] is None and state['registered_at'] is None
    avps,_=request(d,300,private=alias,public=public)
    assert result(d,avps)==('experimental',2001)
    # Metadata was provisioned before the exchange, never learned from MAR/SAR.
    with repo.engine.connect() as c:
        assert c.scalar(select(repo.auc.c.sqn).where(repo.auc.c.auc_id==profiles[1][1]['auc_id']))==0

def test_digest_identity_mapping_does_not_change_real_aka_vectors(lab):
    d,profiles=lab;alias,public,_=configure(d,profiles[1][0])
    avps,_=mar(d,MOBILE_IMPI,MOBILE_IMPU,'Digest-AKAv1-MD5')
    assert result(d,avps)==('base',2001)
    assert bytes.fromhex(d.get_avp_data(avps,1)[0]).decode()==MOBILE_IMPI
    assert len(bytes.fromhex(d.get_avp_data(avps,609)[0]))==32
    avps,_=mar(d,alias,public,'Digest-AKAv1-MD5')
    assert result(d,avps)==('experimental',5006)

def test_cli_provisions_lookup_alias_before_authentication_and_clears_old_pending(lab,monkeypatch):
    d,profiles=lab;repo=d.cx.repo;record=profiles[1][0]
    alias,public,definition=configure(d,record)
    definition['digest_identity_aliases']={}
    repo.provision(record['ims_subscriber_id'],definition,replace=True)
    avps,_=mar(d,alias,public,'SIP Digest')
    assert bytes.fromhex(d.get_avp_data(avps,1)[0]).decode()==alias
    tool=tool_module()
    monkeypatch.setattr(tool,'Database',lambda *args,**kwargs:d.database)
    monkeypatch.setattr(tool,'LogTool',lambda cfg:NullLog())
    monkeypatch.setattr(sys,'argv',['provision_cx_profile.py','--ims-subscriber-id',str(record['ims_subscriber_id']),
        '--private-identity',MOBILE_IMPI,'--private-identity',alias,'--public-identity',public,
        '--authentication-scheme','SIP Digest','--visited-network',REALM,'--set-id','fixed',
        '--preserve-existing','--associate-existing-public','--allow-additional-scheme',
        '--digest-identity-alias',alias,MOBILE_IMPI,'--replace','--clear-authentication-pending'])
    tool.main()
    with repo.engine.connect() as c:
        stored=repo.definition(record,c)
        assert stored['digest_identity_aliases']=={alias:MOBILE_IMPI}
        assert c.scalar(select(func.count()).select_from(repo.states))==0
    avps,_=mar(d,alias,public,'SIP Digest')
    assert bytes.fromhex(d.get_avp_data(avps,1)[0]).decode()==MOBILE_IMPI

@pytest.mark.parametrize('invalid',['unprovisioned','cycle','wrong_public_association','aka_only'])
def test_invalid_digest_mapping_is_rejected_before_provisioning(lab,invalid):
    d,profiles=lab;alias,public,definition=configure(d,profiles[1][0])
    if invalid=='unprovisioned':definition['digest_identity_aliases'][alias]='unprovisioned@'+REALM
    elif invalid=='cycle':definition['digest_identity_aliases'][MOBILE_IMPI]=alias
    elif invalid=='aka_only':definition['authentication_schemes'][MOBILE_IMPI]='Digest-AKAv1-MD5'
    else:
        for item in definition['public_identities']:
            if item['identity']==public:item['private_identities']=[alias]
    with pytest.raises(ValueError):CxRepository.validate_definition(definition)
