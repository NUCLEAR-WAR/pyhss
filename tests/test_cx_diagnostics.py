# Copyright 2026 PyHSS contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path
import importlib.util
import pytest
from sqlalchemy import create_engine,text,select,func
from database import database_connection_settings
from test_cx_registration import lab,IMPI,IMPU,REALM,NullLog,request,result,mar,sar,MOBILE_IMSI,MOBILE_IMPI,MOBILE_IMPU

path=Path(__file__).resolve().parents[1]/'tools/diagnose_cx.py'
spec=importlib.util.spec_from_file_location('diagnose_cx',path)
diagnostics=importlib.util.module_from_spec(spec);spec.loader.exec_module(diagnostics)

@pytest.mark.parametrize('backend',['mysql','mariadb'])
def test_mysql_disable_flag_reaches_actual_driver(backend):
    from pyhss_config import config
    import pymysql
    settings={'db_type':backend,'server':config['hss']['OriginHost'],
              'username':'test-only','password':'','database':'pyhss_test_cx','ssl_disabled':True}
    url,options=database_connection_settings(settings)
    engine=create_engine(url,connect_args=options)
    try:
        args,params=engine.dialect.create_connect_args(url);params.update(options)
        connection=pymysql.connect(*args,**params,defer_connect=True)
        assert options=={'ssl_disabled':True} and connection.ssl is False
    finally:engine.dispose()

@pytest.mark.parametrize('value',['true','false',0,1,None])
def test_tls_disable_setting_requires_yaml_boolean(value):
    with pytest.raises(ValueError,match='YAML boolean'):
        database_connection_settings({'db_type':'mysql','server':REALM,'username':'','password':'',
                                      'database':'pyhss_test_cx','ssl_disabled':value})

def test_tls_flag_does_not_change_other_backends(tmp_path):
    _,options=database_connection_settings({'db_type':'sqlite','database':str(tmp_path/'test.db'),'ssl_disabled':True})
    assert options=={}

def test_diagnosis_checks_exact_identities_and_native_link_without_writes(lab):
    d,_=lab;repo=d.cx.repo
    with repo.engine.connect() as c:
        tables=(repo.identities,repo.states,repo.profiles)
        before=[c.scalar(select(func.count()).select_from(t)) for t in tables]
    report=diagnostics.diagnose(repo.engine,IMPI,IMPU,True)
    assert report['private_identity']['status']=='found'
    assert report['public_identity']['status']=='found'
    assert report['identity_association']=='valid' and report['native_credential_link']=='valid'
    with repo.engine.connect() as c:assert before==[c.scalar(select(func.count()).select_from(t)) for t in tables]

def test_unknown_identity_reports_the_failed_lookup(lab):
    d,_=lab
    report=diagnostics.diagnose(d.database.engine,'unknown@'+REALM,IMPU)
    assert report['private_identity']['status']=='private_identity_not_provisioned'
    assert report['private_identity']['code']==5001
    assert report['public_identity']['status']=='found'

def test_missing_tables_are_reported_without_creating_schema(tmp_path):
    from sqlalchemy import inspect
    engine=create_engine('sqlite:///'+str(tmp_path/'empty.db'))
    try:
        report=diagnostics.diagnose(engine)
        assert 'ims_cx_identity' in report['missing_tables']
        assert inspect(engine).get_table_names()==[]
    finally:engine.dispose()

def test_unknown_identity_logs_reason_and_preserves_wire_result(lab):
    d,_=lab;logs=[]
    d.logTool.log=lambda **kw:logs.append(kw['message'])
    avps,_=request(d,300,private='unknown@'+REALM)
    assert result(d,avps)==('experimental',5001)
    assert any('private_identity_not_provisioned' in line for line in logs)
    assert all(IMPI not in line and IMPU not in line for line in logs)

def test_legacy_sim_aka_registration_needs_no_explicit_cx_identity_rows(lab):
    from sqlalchemy import delete
    from pyhss_config import config
    d,profiles=lab;repo=d.cx.repo;ident=profiles[1][0]['ims_subscriber_id']
    with repo.engine.begin() as c:
        c.execute(delete(repo.identities).where(repo.identities.c.ims_subscriber_id==ident))
        c.execute(delete(repo.profiles).where(repo.profiles.c.ims_subscriber_id==ident))
    realm='ims.mnc'+config['hss']['MNC'].zfill(3)+'.mcc'+config['hss']['MCC']+'.3gppnetwork.org'
    private=MOBILE_IMSI+'@'+realm;public='sip:'+private
    extra=d.cx.avp(600,realm,10415)
    avps,_=request(d,300,private,public,extra=extra,omit=(600,))
    assert result(d,avps)==('experimental',2001)
    avps,_=mar(d,private,public,'Digest-AKAv1-MD5')
    assert result(d,avps)==('base',2001)
    assert bytes.fromhex(d.get_avp_data(avps,608)[0]).decode()=='Digest-AKAv1-MD5'
    assert len(bytes.fromhex(d.get_avp_data(avps,609)[0]))==32
    avps,_=sar(d,1,private,public)
    assert result(d,avps)==('base',2001)
    assert '<PrivateID>'+private+'</PrivateID>' in bytes.fromhex(d.get_avp_data(avps,606)[0]).decode()
    with repo.engine.connect() as c:
        assert c.scalar(select(func.count()).select_from(repo.identities).where(repo.identities.c.ims_subscriber_id==ident))==0
        assert c.scalar(select(func.count()).select_from(repo.profiles).where(repo.profiles.c.ims_subscriber_id==ident))==0
        assert c.scalar(select(repo.ims.c.scscf_timestamp).where(repo.ims.c.ims_subscriber_id==ident)) is not None

@pytest.mark.parametrize('scheme',['Digest-MD5','SIP Digest','Unknown','unknown'])
def test_wrong_scheme_for_legacy_sim_never_consumes_sqn_or_changes_registration(lab,scheme):
    from sqlalchemy import delete
    from pyhss_config import config
    d,profiles=lab;repo=d.cx.repo;ident=profiles[1][0]['ims_subscriber_id']
    with repo.engine.begin() as c:
        c.execute(delete(repo.identities).where(repo.identities.c.ims_subscriber_id==ident))
        c.execute(delete(repo.profiles).where(repo.profiles.c.ims_subscriber_id==ident))
    realm='ims.mnc'+config['hss']['MNC'].zfill(3)+'.mcc'+config['hss']['MCC']+'.3gppnetwork.org'
    private=MOBILE_IMSI+'@'+realm;public='sip:'+private
    avps,_=mar(d,private,public,scheme)
    assert result(d,avps)==('experimental',5006)
    with repo.engine.connect() as c:
        assert c.scalar(select(repo.auc.c.sqn).where(repo.auc.c.auc_id==profiles[1][1]['auc_id']))==0
        assert c.scalar(select(func.count()).select_from(repo.states))==0

def test_explicit_cli_provisioning_creates_no_runtime_assignment(lab,monkeypatch,tmp_path):
    import sys
    from sqlalchemy import delete
    from cx_repository import CxRepository
    d,profiles=lab;repo=d.cx.repo;ident=profiles[0][0]['ims_subscriber_id']
    with repo.engine.begin() as c:
        c.execute(delete(repo.identities).where(repo.identities.c.ims_subscriber_id==ident))
        c.execute(delete(repo.profiles).where(repo.profiles.c.ims_subscriber_id==ident))
    # Reproduce the dump's empty Cx tables plus legacy IMSI/no-plus template.
    from sqlalchemy import update
    template=tmp_path/'legacy-ifc.xml'
    template.write_text('<IMSSubscription><PrivateID>{{ iFC_vars.imsi }}@'+REALM+
        '</PrivateID><ServiceProfile><PublicIdentity><Identity>sip:{{ iFC_vars.msisdn }}@'+REALM+
        '</Identity></PublicIdentity></ServiceProfile></IMSSubscription>')
    with repo.engine.begin() as c:
        c.execute(update(repo.ims).where(repo.ims.c.ims_subscriber_id==ident).values(ifc_path=str(template)))
    avps,_=request(d,300)
    assert result(d,avps)==('experimental',5001)
    report=diagnostics.diagnose(repo.engine,IMPI,IMPU)
    assert report['public_identity']['status']=='public_identity_not_provisioned'
    path=Path(__file__).resolve().parents[1]/'tools/provision_cx_profile.py'
    spec=importlib.util.spec_from_file_location('provision_cx_profile',path)
    tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
    monkeypatch.setattr(tool,'Database',lambda *args,**kwargs:d.database)
    monkeypatch.setattr(tool,'LogTool',lambda cfg:NullLog())
    monkeypatch.setattr(sys,'argv',[str(path),'--ims-subscriber-id',str(ident),
        '--private-identity',IMPI,'--public-identity',IMPU,
        '--authentication-scheme','SIP Digest','--visited-network',REALM])
    tool.main()
    profile=repo.resolve(IMPU,IMPI)
    assert profile['record']['ims_subscriber_id']==ident
    avps,_=request(d,300)
    assert result(d,avps)==('experimental',2001)
    with repo.engine.connect() as c:
        assert c.scalar(select(func.count()).select_from(repo.states))==0
        assert c.scalar(select(repo.ims.c.scscf_timestamp).where(repo.ims.c.ims_subscriber_id==ident)) is None

def test_preserving_mobile_profile_adds_fixed_alias_with_separate_policy(lab):
    import uuid
    from cx_repository import CxRepository
    d,profiles=lab;repo=d.cx.repo;record=profiles[1][0]
    path=Path(__file__).resolve().parents[1]/'tools/provision_cx_profile.py'
    spec=importlib.util.spec_from_file_location('provision_preserve',path)
    tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
    with repo.engine.connect() as c:existing=repo.definition(record,c)
    private=uuid.uuid4().hex+'@'+REALM;public='sip:'+private
    merged=tool.preserve_definition(existing,{'private_identities':[private],
        'public_identities':[{'identity':public,'set_id':'fixed','barred':False}],
        'authentication_scheme':'SIP Digest','digest_realm':REALM,'visited_networks':[REALM]})
    repo.provision(record['ims_subscriber_id'],merged,replace=True)
    assert repo.authentication_schemes(repo.resolve(MOBILE_IMPU,MOBILE_IMPI))==['Digest-AKAv1-MD5']
    assert repo.authentication_schemes(repo.resolve(public,private))==['SIP Digest']
    avps,_=mar(d,MOBILE_IMPI,MOBILE_IMPU,'Digest-AKAv1-MD5')
    assert result(d,avps)==('base',2001)
    avps,_=mar(d,private,public,'SIP Digest')
    assert result(d,avps)==('base',2001) and d.get_avp_data(avps,635)
    with repo.engine.connect() as c:
        assert c.scalar(select(repo.auc.c.sqn).where(repo.auc.c.auc_id==profiles[1][1]['auc_id']))==1

def test_imsi_softphone_policy_extension_is_explicit_and_keeps_aka(lab):
    d,profiles=lab;repo=d.cx.repo;record=profiles[1][0]
    path=Path(__file__).resolve().parents[1]/'tools/provision_cx_profile.py'
    spec=importlib.util.spec_from_file_location('provision_dual',path)
    tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
    with repo.engine.connect() as c:existing=repo.definition(record,c)
    extra={'private_identities':[MOBILE_IMPI],
        'public_identities':[dict(existing['public_identities'][0])],
        'authentication_scheme':'SIP Digest','digest_realm':REALM,'visited_networks':[REALM]}
    with pytest.raises(ValueError,match='allow-additional-scheme'):tool.preserve_definition(existing,extra)
    merged=tool.preserve_definition(existing,extra,allow_additional_scheme=True)
    repo.provision(record['ims_subscriber_id'],merged,replace=True)
    assert repo.authentication_schemes(repo.resolve(MOBILE_IMPU,MOBILE_IMPI))==['Digest-AKAv1-MD5','SIP Digest']
    for scheme,expected in [('SIP Digest','SIP Digest'),('Unknown','SIP Digest'),('unknown','SIP Digest'),('Digest-AKAv1-MD5','Digest-AKAv1-MD5')]:
        avps,_=mar(d,MOBILE_IMPI,MOBILE_IMPU,scheme)
        assert result(d,avps)==('base',2001)
        assert bytes.fromhex(d.get_avp_data(avps,608)[0]).decode()==expected
    # Allowing standard Digest never implicitly allows the nonstandard alias.
    avps,_=mar(d,MOBILE_IMPI,MOBILE_IMPU,'Digest-MD5')
    assert result(d,avps)==('experimental',5006)
    with repo.engine.connect() as c:
        assert c.scalar(select(repo.auc.c.sqn).where(repo.auc.c.auc_id==profiles[1][1]['auc_id']))==1

def test_cli_preserves_legacy_sim_while_enabling_imsi_softphone(lab,monkeypatch):
    import sys
    from sqlalchemy import delete
    from pyhss_config import config
    d,profiles=lab;repo=d.cx.repo;ident=profiles[1][0]['ims_subscriber_id']
    with repo.engine.begin() as c:
        c.execute(delete(repo.identities).where(repo.identities.c.ims_subscriber_id==ident))
        c.execute(delete(repo.profiles).where(repo.profiles.c.ims_subscriber_id==ident))
    realm='ims.mnc'+config['hss']['MNC'].zfill(3)+'.mcc'+config['hss']['MCC']+'.3gppnetwork.org'
    private=MOBILE_IMSI+'@'+realm;public='sip:'+private
    path=Path(__file__).resolve().parents[1]/'tools/provision_cx_profile.py'
    spec=importlib.util.spec_from_file_location('provision_legacy_dual',path)
    tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
    monkeypatch.setattr(tool,'Database',lambda *args,**kwargs:d.database)
    monkeypatch.setattr(tool,'LogTool',lambda cfg:NullLog())
    monkeypatch.setattr(sys,'argv',[str(path),'--ims-subscriber-id',str(ident),
        '--private-identity',private,'--public-identity',public,
        '--authentication-scheme','SIP Digest','--visited-network',realm,
        '--preserve-existing','--allow-additional-scheme'])
    tool.main()
    profile=repo.resolve(public,private)
    assert repo.authentication_schemes(profile)==['Digest-AKAv1-MD5','SIP Digest']
    with repo.engine.connect() as c:assert c.scalar(select(func.count()).select_from(repo.states))==0
    avps,_=request(d,300,private,public,extra=d.cx.avp(600,realm,10415),omit=(600,))
    assert result(d,avps)==('experimental',2001)
    for scheme in ('SIP Digest','Digest-AKAv1-MD5'):
        avps,_=mar(d,private,public,scheme)
        assert result(d,avps)==('base',2001)
