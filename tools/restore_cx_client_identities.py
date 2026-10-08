# Copyright 2026 PyHSS contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Review/restore bare generated SIP identities and rebuild the Cx index.

Dry run is the default. --apply uses one native DB transaction for the entire
selection, and refuses active subscriptions or conflicting identity ownership.
No subscriber, credential, SQN, service trigger or server address is changed.
"""
import argparse
from copy import deepcopy
import json,re,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lib'))
from sqlalchemy import select,create_engine
from types import SimpleNamespace
from cx_repository import CxRepository


def restored_definition(definition,include_explicit=False):
    d=deepcopy(definition);meta=d.get('provisioning',{})
    managed=set(meta.get('managed_public',[]))
    explicit={x if isinstance(x,str) else x['identity'] for x in meta.get('additional_public_identities',[])}
    replacements={}
    for item in d['public_identities']:
        identity=item['identity']
        # Only the exact global SIP form introduced by the earlier generator.
        # Never strip arbitrary URI parameters, local contexts or service IDs.
        if re.fullmatch(r'sips?:\+[1-9][0-9]{0,14}@[^;?@]+;user=phone',identity):
            if include_explicit or (identity in managed and identity not in explicit):
                replacements[identity]=identity[:-len(';user=phone')]
    for item in d['public_identities']:item['identity']=replacements.get(item['identity'],item['identity'])
    if len({x['identity'] for x in d['public_identities']})!=len(d['public_identities']):
        raise ValueError('Restoration would merge existing identities; review their policies explicitly')
    if 'managed_public' in meta:meta['managed_public']=[replacements.get(x,x) for x in meta['managed_public']]
    if include_explicit:
        for item in meta.get('additional_public_identities',[]):
            if isinstance(item,dict):item['identity']=replacements.get(item['identity'],item['identity'])
        if 'additional_public_identities' in meta:
            meta['additional_public_identities']=[replacements.get(x,x) if isinstance(x,str) else x for x in meta['additional_public_identities']]
    return d,replacements


def restore(repo,profile_ids,apply=False,include_explicit=False,clear_authentication_pending=False):
    report=[]
    with repo.transaction(profile_ids) as c:
        for ident in sorted(set(profile_ids)):
            record=repo.record(ident,c)
            raw=c.scalar(select(repo.profiles.c.definition).where(repo.profiles.c.ims_subscriber_id==ident))
            if raw is None:raise ValueError('No explicit Cx profile for selected subscription')
            d,replacements=restored_definition(json.loads(raw),include_explicit)
            d=repo.prepare_definition(record,d)
            actual={(row.identity,row.kind) for row in c.execute(select(repo.identities).where(repo.identities.c.ims_subscriber_id==ident))}
            wanted={(x,'private') for x in d['private_identities'] if x not in d.get('digest_identity_aliases',{})}
            wanted.update((x['identity'],'public') for x in d['public_identities'])
            changed=bool(replacements or actual!=wanted)
            state=c.execute(select(repo.states.c.scscf).where(repo.states.c.ims_subscriber_id==ident)).first()
            assigned=bool((state and state[0]) or record.get('scscf_timestamp'))
            if apply and changed:repo.provision(ident,d,replace=True,connection=c,clear_authentication_pending=clear_authentication_pending)
            report.append({'ims_subscriber_id':ident,'sip_identity_replacements':replacements,
                'index_rows_before':len(actual),'index_rows_after':len(wanted),
                'removed_digest_lookup_rows':sorted(x for x,k in actual-wanted if k=='private' and x in d.get('digest_identity_aliases',{})),
                'assignment_present':assigned,'changed':changed,'applied':bool(apply and changed)})
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    selection=parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--ims-subscriber-id',type=int,action='append')
    selection.add_argument('--all',action='store_true',help='Select all explicitly provisioned Cx profiles')
    parser.add_argument('--include-explicit-phone-sip',action='store_true',help='Also restore manually provisioned global SIP URIs ending exactly in ;user=phone; review dry run first')
    parser.add_argument('--apply',action='store_true',help='Commit reviewed changes after de-registration; default is read-only review')
    parser.add_argument('--clear-authentication-pending',action='store_true',help='Explicitly cancel unfinished authentication only; never clears registered or stored service assignments')
    args=parser.parse_args()
    from database import database_connection_settings
    from pyhss_config import config
    url,options=database_connection_settings(config['database'])
    engine=create_engine(url,connect_args=options,echo=False,hide_parameters=True)
    if engine.dialect.name in ('mysql','postgresql') and config['database'].get('discovery'):
        from service_discovery import install_database_discovery
        install_database_discovery(engine,config['database']['discovery'])
    try:
        repo=CxRepository(SimpleNamespace(engine=engine),config,initialize_schema=False)
        ids=args.ims_subscriber_id
        if args.all:
            with engine.connect() as c:ids=list(c.scalars(select(repo.profiles.c.ims_subscriber_id)))
        print(json.dumps({'mode':'apply' if args.apply else 'dry-run','profiles':restore(repo,ids,args.apply,args.include_explicit_phone_sip,args.clear_authentication_pending)},indent=2))
    finally:engine.dispose()


if __name__=='__main__':main()
