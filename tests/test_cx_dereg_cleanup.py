# Copyright 2026 PyHSS contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
from copy import deepcopy
import pytest
from sqlalchemy import select,func
from test_cx_registration import lab,IMPI,IMPU,REALM,SERVER,request,result,mar,sar,snapshot

def add_private(d,record):
    repo=d.cx.repo;private='other-private@'+REALM
    with repo.engine.connect() as c:definition=repo.definition(record,c)
    definition['private_identities'].append(private)
    for public in definition['public_identities']:public['private_identities']=definition['private_identities']
    repo.provision(record['ims_subscriber_id'],definition,replace=True)
    return private

@pytest.mark.parametrize('typ',[4,5,8,11])
def test_last_registered_impi_releases_assignment_despite_other_pending_challenge(lab,typ):
    d,profiles=lab;repo=d.cx.repo;other=add_private(d,profiles[0][0])
    # Same sequence as the successful captures: challenge a bootstrap IMPI,
    # then authenticate/register the real IMPI in the same implicit set.
    mar(d,private=other);mar(d);sar(d,1)
    state=snapshot(d);assert state['groups']['voice']['pending']==[other]
    assert state['groups']['voice']['registered']==[IMPI]
    with repo.engine.connect() as c:
        identities=c.scalar(select(func.count()).select_from(repo.identities))
    avps,_=sar(d,typ);assert result(d,avps)==('base',2001)
    state=snapshot(d)
    assert state['scscf'] is None and state['realm'] is None and state['peer'] is None
    assert state['registered_at'] is None
    assert state['groups']['voice']=={'state':'not_registered','registered':[],'pending':[],'known_private':[]}
    with repo.engine.connect() as c:
        row=c.execute(select(repo.ims).where(repo.ims.c.ims_subscriber_id==profiles[0][0]['ims_subscriber_id'])).mappings().one()
        assert all(row[field] is None for field in ('scscf','scscf_realm','scscf_peer','scscf_timestamp'))
        assert c.scalar(select(func.count()).select_from(repo.identities))==identities
    avps,_=request(d,300);assert result(d,avps)==('experimental',2001)

def test_deregistering_one_of_two_registered_privates_retains_other_registration_and_pending(lab):
    d,profiles=lab;other=add_private(d,profiles[0][0])
    mar(d);sar(d,1);mar(d,private=other);sar(d,1,private=other)
    # A re-authentication for the departing IMPI must not disturb the other UE.
    mar(d)
    avps,_=sar(d,5);assert result(d,avps)==('base',2001)
    state=snapshot(d,private=other)
    assert state['scscf']==SERVER and state['registered_at'] is not None
    assert state['groups']['voice']['registered']==[other]

def test_deregistration_retains_assignments_and_pending_for_another_implicit_set(lab):
    d,profiles=lab;repo=d.cx.repo
    with repo.engine.connect() as c:definition=repo.definition(profiles[0][0],c)
    public='sip:other-set@'+REALM
    definition['public_identities'].append({'identity':public,'set_id':'other','barred':False})
    repo.provision(profiles[0][0]['ims_subscriber_id'],definition,replace=True)
    mar(d);sar(d,1);mar(d,public=public);sar(d,1,public=public)
    avps,_=sar(d,5);assert result(d,avps)==('base',2001)
    state=snapshot(d)
    assert state['scscf']==SERVER and state['groups']['other']['registered']==[IMPI]
    assert not state['groups']['voice']['registered']

@pytest.mark.parametrize('typ',[6,7])
def test_store_server_deregistration_still_retains_assignment(lab,typ):
    d,profiles=lab;other=add_private(d,profiles[0][0])
    mar(d,private=other);mar(d);sar(d,1)
    avps,_=sar(d,typ);assert result(d,avps)==('base',2001)
    state=snapshot(d)
    assert state['scscf']==SERVER and state['groups']['voice']['state']=='unregistered'
