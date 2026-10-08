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

def main():
    p=argparse.ArgumentParser(description=__doc__)
    selectors=p.add_mutually_exclusive_group(required=True)
    selectors.add_argument('--ims-subscriber-id',type=int);selectors.add_argument('--msisdn')
    p.add_argument('--profile',required=True,help='JSON with exact private/public identities and authentication policy')
    p.add_argument('--replace',action='store_true',help='Replace an existing explicitly provisioned profile after de-registration')
    args=p.parse_args()
    db=Database(LogTool(config),main_service=False);repo=CxRepository(db,config)
    with db.engine.connect() as c:
        if args.ims_subscriber_id:ident=args.ims_subscriber_id
        else:
            value=args.msisdn;values={value,value.lstrip('+'),'+'+value.lstrip('+')}
            rows=c.execute(select(repo.ims.c.ims_subscriber_id).where(repo.ims.c.msisdn.in_(values))).all()
            if len(rows)!=1:raise ValueError('MSISDN selector is unknown or ambiguous')
            ident=rows[0][0]
    definition=json.loads(Path(args.profile).read_text())
    repo.provision(ident,definition,args.replace)
    print(f'Provisioned Cx identities for IMS subscriber #{ident}; no registration or S-CSCF was assigned')

if __name__=='__main__':main()
