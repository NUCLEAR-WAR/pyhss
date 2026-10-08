# Copyright 2026 PyHSS contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path
import hashlib,importlib.util,sys
import pytest
from sqlalchemy import select,func
from test_cx_registration import lab,REALM,MOBILE_IMPI,MOBILE_IMPU,digits,request,result,mar,sar,NullLog

def tool_module():
    path=Path(__file__).resolve().parents[1]/'tools/provision_cx_profile.py'
    spec=importlib.util.spec_from_file_location('provision_associations',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def fixed_alias(d,record):
    tool=tool_module();repo=d.cx.repo
    private='+'+digits(11)+'@'+REALM;public='sip:'+private+';user=phone';tel='tel:'+private.partition('@')[0]
    with repo.engine.connect() as c:existing=repo.definition(record,c)
    extra={'private_identities':[private],
        'public_identities':[{'identity':identity,'set_id':'fixed','barred':False} for identity in (public,tel)],
        'authentication_scheme':'SIP Digest','digest_realm':REALM,'visited_networks':[REALM]}
    merged=tool.preserve_definition(existing,extra)
    repo.provision(record['ims_subscriber_id'],merged,replace=True)
    return private,public,tel

def test_cli_imsi_private_can_register_msisdn_public_without_losing_aka(lab,monkeypatch):
    d,profiles=lab;repo=d.cx.repo;record=profiles[1][0];ident=record['ims_subscriber_id']
    private,public,tel=fixed_alias(d,record)
    # Reproduce the successful first challenge followed by the 5002 mismatch.
    avps,_=mar(d,private,public,'SIP Digest');assert result(d,avps)==('base',2001)
    avps,_=mar(d,MOBILE_IMPI,public,'SIP Digest');assert result(d,avps)==('experimental',5002)
    with repo.engine.connect() as c:old=repo.definition(record,c)
    tool=tool_module()
    monkeypatch.setattr(tool,'Database',lambda *args,**kwargs:d.database)
    monkeypatch.setattr(tool,'LogTool',lambda cfg:NullLog())
    monkeypatch.setattr(sys,'argv',['provision_cx_profile.py','--ims-subscriber-id',str(ident),
        '--private-identity',MOBILE_IMPI,'--public-identity',public,
        '--authentication-scheme','SIP Digest','--visited-network',REALM,'--set-id','fixed',
        '--preserve-existing','--allow-additional-scheme','--associate-existing-public',
        '--replace','--clear-authentication-pending'])
    tool.main()
    with repo.engine.connect() as c:
        current=repo.definition(record,c)
        assert c.scalar(select(func.count()).select_from(repo.states).where(repo.states.c.ims_subscriber_id==ident))==0
        assert c.scalar(select(repo.ims.c.scscf).where(repo.ims.c.ims_subscriber_id==ident)) is None
        assert c.scalar(select(repo.auc.c.sqn).where(repo.auc.c.auc_id==profiles[1][1]['auc_id']))==0
    for item in old['public_identities']:
        if item['set_id']!='fixed':assert item in current['public_identities']
    for identity in (public,tel):
        profile=repo.resolve(identity,MOBILE_IMPI)
        assert profile['public']['private_identities']==[private,MOBILE_IMPI]
    assert repo.authentication_schemes(repo.resolve(public,MOBILE_IMPI))==['Digest-AKAv1-MD5','SIP Digest']
    before=[item['identity'] for item in current['public_identities']]
    avps,_=request(d,300,private=MOBILE_IMPI,public=public)
    assert result(d,avps)==('experimental',2001)
    avps,_=mar(d,MOBILE_IMPI,public,'SIP Digest')
    assert result(d,avps)==('base',2001)
    expected=hashlib.md5(f'{MOBILE_IMPI}:{REALM}:{profiles[1][1]["ki"]}'.encode()).hexdigest()
    assert bytes.fromhex(d.get_avp_data(avps,121)[0]).decode()==expected
    avps,_=sar(d,1,private=MOBILE_IMPI,public=public)
    assert result(d,avps)==('base',2001)
    xml=bytes.fromhex(d.get_avp_data(avps,606)[0]).decode()
    assert '<PrivateID>'+MOBILE_IMPI+'</PrivateID>' in xml and public in xml and tel in xml
    assert MOBILE_IMPU not in xml
    avps,_=mar(d,MOBILE_IMPI,MOBILE_IMPU,'Digest-AKAv1-MD5')
    assert result(d,avps)==('base',2001)
    with repo.engine.connect() as c:
        assert [item['identity'] for item in repo.definition(record,c)['public_identities']]==before
        assert c.scalar(select(repo.auc.c.sqn).where(repo.auc.c.auc_id==profiles[1][1]['auc_id']))==1

@pytest.mark.parametrize('typ',[1,3])
def test_pending_clear_cannot_remove_registered_or_stored_unregistered_service(lab,typ):
    d,profiles=lab;repo=d.cx.repo;record=profiles[1][0];ident=record['ims_subscriber_id']
    mar(d,MOBILE_IMPI,MOBILE_IMPU,'Digest-AKAv1-MD5')
    sar(d,typ,private=MOBILE_IMPI,public=MOBILE_IMPU)
    with repo.engine.connect() as c:
        definition=repo.definition(record,c)
        profile=repo.resolve(MOBILE_IMPU,MOBILE_IMPI,c)
        before=repo.state(profile,c)
    with pytest.raises(ValueError,match='Cannot clear authentication pending'):
        repo.provision(ident,definition,replace=True,clear_authentication_pending=True)
    with repo.engine.connect() as c:assert repo.state(profile,c)==before

def test_association_extension_requires_explicit_option_and_preserves_public_policy(lab):
    d,profiles=lab;repo=d.cx.repo;record=profiles[1][0]
    private,public,tel=fixed_alias(d,record)
    with repo.engine.connect() as c:existing=repo.definition(record,c)
    extra={'private_identities':[MOBILE_IMPI],
        'public_identities':[{'identity':public,'set_id':'fixed','barred':False}],
        'authentication_scheme':'SIP Digest','digest_realm':REALM}
    tool=tool_module()
    with pytest.raises(ValueError,match='associate-existing-public'):
        tool.preserve_definition(existing,extra,allow_additional_scheme=True)
    extra['public_identities'][0]['barred']=True
    with pytest.raises(ValueError,match='cannot change the public identity policy|no non-barred public identity'):
        tool.preserve_definition(existing,extra,allow_additional_scheme=True,associate_existing_public=True)

def test_failed_profile_replacement_does_not_clear_pending_or_rewrite_credentials(lab):
    d,profiles=lab;repo=d.cx.repo;record=profiles[1][0];ident=record['ims_subscriber_id']
    mar(d,MOBILE_IMPI,MOBILE_IMPU,'Digest-AKAv1-MD5')
    with repo.engine.connect() as c:
        old=repo.definition(record,c);profile=repo.resolve(MOBILE_IMPU,MOBILE_IMPI,c);state=repo.state(profile,c)
    # Duplicate another subscription's identity: the whole replacement must fail.
    from test_cx_registration import IMPI
    proposed=dict(old);proposed['private_identities']=old['private_identities']+[IMPI]
    with pytest.raises(ValueError,match='another subscription'):
        repo.provision(ident,proposed,replace=True,clear_authentication_pending=True)
    with repo.engine.connect() as c:
        assert repo.definition(record,c)==old and repo.state(profile,c)==state
        assert c.scalar(select(repo.auc.c.sqn).where(repo.auc.c.auc_id==profiles[1][1]['auc_id']))==1
