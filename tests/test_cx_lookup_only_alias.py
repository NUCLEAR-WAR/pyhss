# SPDX-License-Identifier: AGPL-3.0-or-later
"""Registration with profile-scoped lookup aliases absent from the IMPI index."""
from copy import deepcopy
import pytest
from sqlalchemy import select
from cx_provisioning import CxProvisioning
from test_cx_registration import (lab,REALM,digits,request,result,mar,sar,snapshot,
    MOBILE_IMPI,MOBILE_IMPU)
from test_cx_api_provisioning import bundle,associated_publics
from test_cx_diagnostics import diagnostics
from pyhss_config import config

def provision(d):
    svc=CxProvisioning(d.database,config);payload=bundle(d)
    ims=svc.create_service(payload)['ims_subscriber'];definition=ims['cx']
    private=definition['provisioning']['private_identity']
    lookup=next(x for x in definition['digest_identity_aliases'] if x.startswith('+'))
    return svc,ims,private,lookup,'sip:'+lookup

def stored(repo):
    with repo.engine.connect() as c:
        return {table.name:list(c.execute(select(table))) for table in (repo.profiles,repo.identities,repo.states,repo.ims,repo.auc)}

def test_indexless_alias_initial_and_registered_uar_are_read_only_and_authenticate_actual_impi(lab):
    d,_=lab;svc,ims,private,lookup,public=provision(d);repo=svc.repo
    with repo.engine.connect() as c:
        private_rows=list(c.scalars(select(repo.identities.c.identity).where(repo.identities.c.ims_subscriber_id==ims['ims_subscriber_id'],repo.identities.c.kind=='private')))
    assert private_rows==[private]
    for source in (lookup,lookup.lstrip('+'),private):
        before=stored(repo)
        avps,_=request(d,300,source,public,extra=d.cx.avp(600,'"'+REALM+'"',10415),omit=(600,))
        assert result(d,avps)==('experimental',2001);assert stored(repo)==before
    avps,_=mar(d,lookup,public);assert result(d,avps)==('base',2001)
    assert bytes.fromhex(d.get_avp_data(avps,1)[0]).decode()==private
    avps,_=sar(d,1,private,public);assert result(d,avps)==('base',2001)
    assert not d.get_avp_data(avps,632)
    assert sorted(associated_publics(d,avps))==sorted([public,'tel:'+lookup.partition('@')[0]])
    before=stored(repo)
    for source in (lookup,lookup.lstrip('+'),private):
        avps,_=request(d,300,source,public,extra=d.cx.avp(600,'"'+REALM+'"',10415),omit=(600,))
        assert result(d,avps)==('experimental',2002)
        assert stored(repo)==before
    avps,_=sar(d,2,private,public);assert result(d,avps)==('base',2001)
    assert snapshot(d,private,public)['groups']['fixed']['registered']==[private]
    avps,_=sar(d,5,private,public);assert result(d,avps)==('base',2001)
    assert snapshot(d,private,public)['scscf'] is None

def test_pending_deregistration_uar_uses_canonical_authentication_impi(lab):
    d,_=lab;_,_,private,lookup,public=provision(d)
    mar(d,lookup,public);before=snapshot(d,private,public)
    avps,_=request(d,300,lookup,public,extra=d.cx.avp(623,1,10415,True))
    assert result(d,avps)==('base',2001)
    assert snapshot(d,private,public)==before

def test_lookup_alias_is_not_accepted_as_a_sar_registration_impi(lab):
    d,_=lab;svc,_,private,lookup,public=provision(d)
    mar(d,lookup,public);before=stored(svc.repo)
    avps,_=sar(d,1,lookup,public);assert result(d,avps)==('experimental',5002)
    assert stored(svc.repo)==before

def test_known_alias_cannot_impersonate_a_private_identity_owned_by_another_profile(lab):
    d,profiles=lab;svc,ims,private,lookup,public=provision(d)
    with svc.repo.engine.begin() as c:
        c.execute(svc.repo.identities.insert().values(identity=lookup,kind='private',ims_subscriber_id=profiles[0][0]['ims_subscriber_id']))
    before=stored(svc.repo)
    avps,_=request(d,300,lookup,public);assert result(d,avps)==('experimental',5002)
    assert stored(svc.repo)==before

def test_unknown_alias_and_wrong_uri_parameters_remain_rejected(lab):
    d,_=lab;_,_,_,lookup,public=provision(d)
    avps,_=request(d,300,'unknown-'+digits(5)+'@'+REALM,public);assert result(d,avps)==('experimental',5001)
    avps,_=request(d,300,lookup,public+';user=phone');assert result(d,avps)==('experimental',5001)
    avps,_=request(d,300,'sip:'+lookup,public);assert result(d,avps)==('experimental',5001)

def test_read_only_diagnostics_recognizes_alias_without_private_index_row(lab):
    d,_=lab;svc,_,private,lookup,public=provision(d)
    before=stored(svc.repo);report=diagnostics.diagnose(svc.repo.engine,lookup,public)
    assert report['private_identity']['role']=='digest_lookup_alias'
    assert report['identity_association']=='valid'
    assert report['digest_authentication_identity']==private
    assert stored(svc.repo)==before

def test_real_sim_aka_is_unchanged_and_alias_cannot_select_aka(lab):
    d,_=lab;svc,_,_,lookup,public=provision(d)
    before=stored(svc.repo)
    avps,_=mar(d,lookup,public,'Digest-AKAv1-MD5');assert result(d,avps)==('experimental',5006)
    assert stored(svc.repo)==before
    avps,_=mar(d,MOBILE_IMPI,MOBILE_IMPU,'Digest-AKAv1-MD5');assert result(d,avps)==('base',2001)
    assert bytes.fromhex(d.get_avp_data(avps,1)[0]).decode()==MOBILE_IMPI
    assert len(bytes.fromhex(d.get_avp_data(avps,609)[0]))==32

def test_provisioning_saves_keep_real_impi_index_only(lab):
    d,_=lab;svc,ims,private,lookup,public=provision(d);ident=ims['ims_subscriber_id']
    updated=svc.save({'ifc_path':'default_ifc.xml','cx':{'authentication':'sip_digest'}},ident)
    with svc.repo.engine.connect() as c:
        ids=list(c.scalars(select(svc.repo.identities.c.identity).where(svc.repo.identities.c.kind=='private',svc.repo.identities.c.ims_subscriber_id==ident)))
    assert ids==[private]
    assert public in [x['identity'] for x in updated['cx']['public_identities']]
    assert public+';user=phone' not in [x['identity'] for x in updated['cx']['public_identities']]
