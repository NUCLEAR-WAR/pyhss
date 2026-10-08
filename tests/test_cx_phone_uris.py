# Copyright 2026 PyHSS contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Telephone URI semantics, exact public identity matching and wire procedures."""
import pytest
from cx_provisioning import CxProvisioning
from test_cx_api_provisioning import bundle,totals,associated_publics
from test_cx_registration import lab,REALM,digits,request,result,mar,sar,SERVER
from pyhss_config import config

@pytest.mark.parametrize('form,reason',[
    ('local_no_context','requires phone-context'),
    ('misplaced_context','must precede @'),
])
def test_invalid_telephone_sip_identity_rolls_back_complete_service(lab,form,reason):
    d,_=lab;svc=CxProvisioning(d.database,config);payload=bundle(d);before=totals(d);number=digits(4)
    identities={'bare_global':'sip:+'+digits(11)+'@'+REALM,
        'bare_local':'sip:'+number+'@'+REALM,
        'same_impi_local':'sip:'+payload['subscriber']['imsi']+'@'+REALM,
        'local_no_context':'sip:'+number+'@'+REALM+';user=phone',
        'misplaced_context':'sip:'+number+'@'+REALM+';phone-context='+REALM+';user=phone',
        'context_no_phone':'sip:'+number+';phone-context='+REALM+'@'+REALM}
    payload['ims_subscriber']['cx']['additional_public_identities']=[identities[form]]
    with pytest.raises(ValueError,match=reason):svc.create_service(payload)
    assert totals(d)==before

def test_generic_nontelephone_sip_username_is_not_tagged_as_phone(lab):
    d,_=lab;svc=CxProvisioning(d.database,config);payload=bundle(d);username='service-'+digits(6)
    identity='sip:'+username+'@'+REALM
    payload['ims_subscriber']['cx']['additional_public_identities']=[identity]
    ims=svc.create_service(payload)['ims_subscriber'];private=ims['cx']['provisioning']['private_identity']
    avps,_=mar(d,private,identity);assert result(d,avps)==('base',2001)
    avps,_=sar(d,1,private,identity);assert result(d,avps)==('base',2001)
    assert identity in associated_publics(d,avps)
    assert identity+';user=phone' not in associated_publics(d,avps)

def test_new_phone_public_identity_parameters_remain_significant_and_server_name_is_preserved(lab):
    d,_=lab;svc=CxProvisioning(d.database,config);payload=bundle(d)
    ims=svc.create_service(payload)['ims_subscriber'];private=ims['cx']['provisioning']['private_identity']
    unmarked='sip:+'+payload['subscriber']['msisdn']+'@'+REALM;public=unmarked
    avps,_=request(d,300,private,unmarked+';user=phone');assert result(d,avps)==('experimental',5001)
    avps,_=request(d,300,private,public);assert result(d,avps)==('experimental',2001)
    assert not d.get_avp_data(avps,602)
    avps,_=mar(d,private,public,server=SERVER);assert result(d,avps)==('base',2001)
    avps,_=request(d,300,private,public);assert result(d,avps)==('experimental',2002)
    assert bytes.fromhex(d.get_avp_data(avps,602)[0]).decode()==SERVER
    avps,_=sar(d,1,private,public,server=SERVER);assert result(d,avps)==('base',2001)
    avps,_=sar(d,5,private,public,server=SERVER);assert result(d,avps)==('base',2001)
    with svc.repo.engine.connect() as c:
        profile=svc.repo.resolve(public,private,c);assert svc.repo.state(profile,c)['scscf'] is None

def test_phone_shaped_custom_impi_does_not_duplicate_or_bar_its_calling_identity(lab):
    d,_=lab;svc=CxProvisioning(d.database,config);payload=bundle(d)
    private='+'+payload['subscriber']['msisdn']+'@'+REALM;public='sip:'+private
    payload['ims_subscriber']['cx']['private_identity']=private
    ims=svc.create_service(payload)['ims_subscriber']
    assert [p['identity'] for p in ims['cx']['public_identities']].count(public)==1
    avps,_=mar(d,private,public);assert result(d,avps)==('base',2001)
    avps,_=sar(d,1,private,public);assert result(d,avps)==('base',2001)
    assert public in associated_publics(d,avps)

@pytest.mark.parametrize('kind',['global','local','local_context'])
def test_explicit_bare_sip_service_user_is_stored_without_added_parameters(lab,kind):
    d,_=lab;svc=CxProvisioning(d.database,config);payload=bundle(d)
    user='+'+digits(11) if kind=='global' else digits(4)
    if kind=='local_context':user+=';phone-context='+REALM
    public='sip:'+user+'@'+REALM
    payload['ims_subscriber']['cx']['additional_public_identities']=[public]
    ims=svc.create_service(payload)['ims_subscriber'];private=ims['cx']['provisioning']['private_identity']
    avps,_=mar(d,private,public);assert result(d,avps)==('base',2001)
    avps,_=sar(d,1,private,public);assert result(d,avps)==('base',2001)
    assert public in associated_publics(d,avps)
    assert public+';user=phone' not in associated_publics(d,avps)
