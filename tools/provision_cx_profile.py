# Copyright 2026 PyHSS contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Explicitly provision IMS identities before registration, in the PyHSS DB."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lib'))
from sqlalchemy import select
from database import Database
from logtool import LogTool
from pyhss_config import config
from cx_repository import CxRepository
from copy import deepcopy

def preserve_definition(existing,additional,allow_additional_scheme=False):
    """Explicit operator merge; never infer authentication policy from a request."""
    base=CxRepository.validate_definition(existing)
    extra=CxRepository.validate_definition(additional)
    if base['digest_realm']!=extra['digest_realm']:
        raise ValueError('Use an explicit JSON profile for identities with different Digest realms')
    schemes=deepcopy(base.get('authentication_schemes',{}))
    for private in base['private_identities']:schemes.setdefault(private,base['authentication_scheme'])
    for private in extra['private_identities']:
        scheme=extra.get('authentication_schemes',{}).get(private,extra['authentication_scheme'])
        current=schemes.get(private)
        if current is not None:
            current=[current] if isinstance(current,str) else current
            requested=[scheme] if isinstance(scheme,str) else scheme
            if not set(requested)<=set(current) and not allow_additional_scheme:
                raise ValueError('Use --allow-additional-scheme to explicitly extend an existing private identity policy')
            schemes[private]=list(dict.fromkeys(current+requested))
        else:schemes[private]=scheme
    base['authentication_schemes']=schemes
    base['private_identities']=list(dict.fromkeys(base['private_identities']+extra['private_identities']))
    by_identity={item['identity']:item for item in base['public_identities']}
    for item in extra['public_identities']:
        if item['identity'] in by_identity:
            if item!=by_identity[item['identity']]:raise ValueError('Use an explicit JSON profile to change an existing public identity association')
            continue
        base['public_identities'].append(item)
    base['visited_networks']=list(dict.fromkeys((base.get('visited_networks') or [base['digest_realm']])+extra.get('visited_networks',[])))
    return CxRepository.validate_definition(base)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    selectors=p.add_mutually_exclusive_group(required=True)
    selectors.add_argument('--ims-subscriber-id',type=int);selectors.add_argument('--msisdn')
    p.add_argument('--profile',help='JSON with exact private/public identities and authentication policy')
    p.add_argument('--private-identity',action='append',help='Full provisioned IMPI; repeat for aliases')
    p.add_argument('--public-identity',action='append',help='Exact provisioned IMPU URI; repeat for an implicit set')
    p.add_argument('--authentication-scheme',choices=['SIP Digest','Digest-AKAv1-MD5'])
    p.add_argument('--digest-realm',help='Defaults to the supplied private identity realm')
    p.add_argument('--visited-network',action='append',help='Permitted visited network; repeat as needed')
    p.add_argument('--set-id',default='default',help='Implicit registration set for identities supplied on the command line')
    p.add_argument('--unregistered-service',action='store_true')
    p.add_argument('--preserve-existing',action='store_true',help='Retain existing/legacy identities and their authentication policies while adding explicit aliases')
    p.add_argument('--allow-additional-scheme',action='store_true',help='Explicitly allow another scheme for an existing private identity while preserving its current scheme')
    p.add_argument('--replace',action='store_true',help='Replace an existing explicitly provisioned profile after de-registration')
    args=p.parse_args()
    if args.allow_additional_scheme and not args.preserve_existing:
        p.error('--allow-additional-scheme requires --preserve-existing')
    inline=any((args.private_identity,args.public_identity,args.authentication_scheme,args.digest_realm,
                args.visited_network,args.unregistered_service,args.set_id!='default'))
    if args.profile and inline:p.error('Choose either --profile or explicit identity/policy arguments')
    if not args.profile:
        if not all((args.private_identity,args.public_identity,args.authentication_scheme,args.visited_network)):
            p.error('Supply --profile or all of --private-identity, --public-identity, --authentication-scheme and --visited-network')
        definition={
            'private_identities':args.private_identity,
            'public_identities':[{'identity':identity,'set_id':args.set_id,'barred':False} for identity in args.public_identity],
            'authentication_scheme':args.authentication_scheme,
            'digest_realm':args.digest_realm or args.private_identity[0].rpartition('@')[2],
            'visited_networks':args.visited_network,'unregistered_service':args.unregistered_service}
    else:definition=json.loads(Path(args.profile).read_text())
    db=Database(LogTool(config),main_service=False);repo=CxRepository(db,config)
    with db.engine.connect() as c:
        if args.ims_subscriber_id:ident=args.ims_subscriber_id
        else:
            value=args.msisdn;values={value,value.lstrip('+'),'+'+value.lstrip('+')}
            rows=c.execute(select(repo.ims.c.ims_subscriber_id).where(repo.ims.c.msisdn.in_(values))).all()
            if len(rows)!=1:raise ValueError('MSISDN selector is unknown or ambiguous')
            ident=rows[0][0]
        if args.preserve_existing:
            record=repo.record(ident,c)
            definition=preserve_definition(repo.definition(record,c),definition,args.allow_additional_scheme)
    repo.provision(ident,definition,args.replace)
    print(f'Provisioned Cx identities for IMS subscriber #{ident}; no registration or S-CSCF was assigned')

if __name__=='__main__':main()
