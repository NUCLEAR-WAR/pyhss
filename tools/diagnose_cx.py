# Copyright 2026 PyHSS contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Read-only Cx lookup and MySQL session TLS checks using native DB settings."""
import argparse
import json
import sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lib'))
from sqlalchemy import create_engine,inspect,select,text
from sqlalchemy.exc import SQLAlchemyError
from database import database_connection_settings
from pyhss_config import config
from cx_repository import CxRepository,CxError,private_key
import jinja2
import xml.etree.ElementTree as ET

def diagnose(engine,private=None,public=None,ifc_report=False):
    report={'database_backend':engine.dialect.name}
    # No Database initializer, Cx DDL, provisioning, registration or crypto runs.
    repo=CxRepository(SimpleNamespace(engine=engine),config,initialize_schema=False)
    try:
        repo.network_codes();report['plmn_configuration']='valid'
    except ValueError as error:report['plmn_configuration']=str(error)
    with engine.connect() as c:
        if engine.dialect.name in ('mysql','mariadb'):
            report['database']=c.execute(text('SELECT DATABASE()')).scalar()
            status=c.execute(text("SHOW SESSION STATUS LIKE 'Ssl_cipher'")).first()
            report['mysql_tls_cipher']=status[1] if status else None
            report['mysql_connection_encrypted']=bool(status and status[1])
        elif engine.dialect.name=='postgresql':
            report['database']=c.execute(text('SELECT current_database()')).scalar()
        else:report['database']=engine.url.database
        present=set(inspect(c).get_table_names())
        required={t.name for t in (repo.ims,repo.sub,repo.auc,repo.profiles,repo.identities,repo.states)}
        report['missing_tables']=sorted(required-present)
        if report['missing_tables']:
            report['status']='missing_database_tables';return report
        found={}
        for kind,identity in (('private',private),('public',public)):
            if identity is None:continue
            try:
                record,definition=repo.find(identity,kind,c)
                found[kind]=(record,definition)
                report[kind+'_identity']={'status':'found','ims_subscriber_id':record['ims_subscriber_id']}
            except CxError as error:
                report[kind+'_identity']={'status':error.reason or 'lookup_rejected','code':error.code,'experimental':error.experimental}
            except (ValueError,ET.ParseError,jinja2.TemplateError) as error:
                report[kind+'_identity']={'status':'profile_or_ifc_invalid','error_type':type(error).__name__}
        if private is not None and public is not None:
            # A Digest bootstrap alias has no private-kind index row. It is
            # resolved only within the explicitly provisioned public profile.
            if 'public' in found and 'private' not in found:
                try:
                    profile=repo.resolve(public,private,c)
                    if private_key(private) in profile['definition'].get('digest_identity_aliases',{}):
                        found['private']=(profile['record'],profile['definition'])
                        report['private_identity']={'status':'found','role':'digest_lookup_alias',
                            'ims_subscriber_id':profile['record']['ims_subscriber_id']}
                except (CxError,ValueError):pass
            if len(found)==2:
                try:
                    profile=repo.resolve(public,private,c)
                    report['identity_association']='valid'
                    report['authentication_scheme']=repo.authentication_scheme(profile)
                    report['allowed_authentication_schemes']=repo.authentication_schemes(profile)
                    report['digest_authentication_identity']=profile['definition'].get('digest_identity_aliases',{}).get(profile['private'],profile['private'])
                    subscriber=c.execute(select(repo.sub.c.subscriber_id,repo.sub.c.auc_id,repo.sub.c.enabled)
                        .where(repo.sub.c.imsi==profile['record']['imsi'])).mappings().first()
                    if subscriber is None:report['native_credential_link']='subscriber_not_found'
                    else:
                        report['native_subscriber_enabled']=bool(subscriber['enabled'])
                        auc=c.execute(select(repo.auc.c.auc_id).where(repo.auc.c.auc_id==subscriber['auc_id'])).first()
                        report['native_credential_link']='valid' if auc else 'auc_not_found'
                except CxError as error:
                    report['identity_association']='mismatch' if error.code==5002 else 'lookup_rejected'
            else:report['identity_association']='cannot_validate_missing_identity'
        if ifc_report:
            explicit=set(c.execute(select(repo.profiles.c.ims_subscriber_id)).scalars())
            issues=[];checked=0
            for row in c.execute(select(repo.ims)).mappings():
                if row['ims_subscriber_id'] in explicit:continue
                checked+=1
                try:repo.validate_definition(repo.legacy_profile(dict(row)))
                except (ValueError,ET.ParseError,jinja2.TemplateError) as error:
                    issues.append({'ims_subscriber_id':row['ims_subscriber_id'],
                        'ifc_path':row['ifc_path'],'error_type':type(error).__name__})
            report['legacy_ifc_profiles_checked']=checked
            report['legacy_ifc_issues']=issues
        report['status']='checks_completed'
        return report

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-identity',help='Exact User-Name from the failing UAR')
    parser.add_argument('--public-identity',help='Exact Public-Identity from the failing UAR')
    parser.add_argument('--ifc-report',action='store_true',help='Report invalid legacy IFC profiles by database ID')
    args=parser.parse_args()
    url,options=database_connection_settings(config['database'])
    engine=create_engine(url,connect_args=options,echo=False,hide_parameters=True)
    try:
        result=diagnose(engine,args.private_identity,args.public_identity,args.ifc_report)
        print(json.dumps(result,indent=2))
        if result['missing_tables']:return 2
        if any(result.get(kind+'_identity',{}).get('status') not in (None,'found') for kind in ('private','public')):return 2
        if result.get('identity_association')=='mismatch':return 2
        if result.get('native_credential_link') not in (None,'valid'):return 2
        return 0
    except SQLAlchemyError as error:
        original=getattr(error,'orig',None);details=getattr(original,'args',())
        # Never print a connection URL, SQL parameters or authentication secrets.
        print(json.dumps({'status':'database_connection_or_query_failed',
            'error_type':type(original or error).__name__,
            'database_error_code':details[0] if details and isinstance(details[0],int) else None},indent=2))
        return 3
    finally:engine.dispose()

if __name__=='__main__':raise SystemExit(main())
