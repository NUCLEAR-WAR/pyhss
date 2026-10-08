# Copyright 2026 PyHSS contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Admin HTTP forms -> real native API -> actual SQLAlchemy database."""
import importlib,io,json,os,sqlite3,sys,urllib.error
from urllib.parse import urlsplit,urlencode
from pathlib import Path
import pytest
from test_cx_api_provisioning import api_client,bundle,totals
from test_cx_registration import lab,REALM,digits

@pytest.fixture
def ui_client(api_client,monkeypatch,tmp_path):
    ui_root=os.getenv('PYHSS_CX_UI_ROOT')
    if not ui_root:pytest.skip('Set PYHSS_CX_UI_ROOT to the lab pyhss_admin source directory')
    monkeypatch.syspath_prepend(ui_root)
    sys.modules.pop('pyhss_5gc.admin.app',None)
    ui=importlib.import_module('pyhss_5gc.admin.app');client,module,d=api_client
    class Reply:
        def __init__(self,response):self.status=response.status_code;self.headers=response.headers;self.data=response.data
        def read(self):return self.data
        def __enter__(self):return self
        def __exit__(self,*args):pass
    class Opener:
        def open(self,request,timeout=None):
            path=urlsplit(request.full_url).path
            response=client.open(path,method=request.get_method(),data=request.data,headers=dict(request.header_items()))
            if response.status_code>=400:raise urllib.error.HTTPError(request.full_url,response.status_code,'API error',response.headers,io.BytesIO(response.data))
            return Reply(response)
    monkeypatch.setattr(ui,'_API_OPENER',Opener())
    monkeypatch.setattr(ui,'G5_DB',tmp_path/'fiveg.db');monkeypatch.setattr(ui,'PCF_DB',tmp_path/'pcf.db')
    with sqlite3.connect(ui.G5_DB) as c:
        c.execute('CREATE TABLE udr_5g_slice(imsi,sst,sd,is_default)')
        c.execute('CREATE TABLE udr_5g_slice_apn(imsi,sst,sd,apn_id,is_default,five_qi,arp_priority,session_ambr_ul,session_ambr_dl,pdu_session_type,ssc_mode)')
    # These routes only await request body and ASGI response operations. Drive
    # the real application directly, without Windows' loopback socketpair.
    class Client:
        def request(self,method,url,data=None):
            parsed=urlsplit(url);body=urlencode(data or {}).encode();messages=[]
            async def receive():return {'type':'http.request','body':body,'more_body':False}
            async def send(message):messages.append(message)
            scope={'type':'http','asgi':{'version':'3.0','spec_version':'2.4'},'method':method,'path':parsed.path,'raw_path':parsed.path.encode(),'query_string':parsed.query.encode(),'headers':[(b'content-type',b'application/x-www-form-urlencoded')],'scheme':'http','server':('test',80),'client':('test',1),'http_version':'1.1'}
            coroutine=ui.app(scope,receive,send)
            try:coroutine.send(None)
            except StopIteration:pass
            else:pytest.fail('Unexpected asynchronous I/O in the provisioning route')
            response=type('Response',(),{})()
            response.status_code=next(x['status'] for x in messages if x['type']=='http.response.start')
            response.text=b''.join(x.get('body',b'') for x in messages if x['type']=='http.response.body').decode()
            response.json=lambda:json.loads(response.text)
            return response
        def get(self,url):return self.request('GET',url)
        def post(self,url,data):return self.request('POST',url,data)
    yield Client(),ui,module,d

def test_fixed_ui_provisions_cx_and_preserves_new_barring_preview(ui_client):
    client,ui,module,d=ui_client;imsi=digits(15);number=digits(11)
    form={'profile':'fixed_voice','imsi':imsi,'msisdn':'+'+number,'digest_password':'test-'+digits(16),'cx_realm':REALM,'ifc_path':'default_ifc.xml'}
    response=client.post('/provision',data=form)
    assert 'Native provisioning failed' not in response.text,response.text
    ims=ui.one(ui.PYHSS_DB,'SELECT * FROM ims_subscriber WHERE imsi=?',(imsi,))
    assert ims['cx']['digest_identity_aliases']['+'+number+'@'+REALM]==imsi+'@'+REALM
    preview=client.get('/api/cx/'+str(ims['ims_subscriber_id'])+'/barring')
    assert preview.status_code==200 and preview.json()['source']=='explicit_cx'
    before=totals(d)
    response=client.post('/provision',data=form)
    assert 'Native provisioning failed' in response.text
    assert totals(d)==before
    assert ui.one(ui.PYHSS_DB,'SELECT * FROM ims_subscriber WHERE imsi=?',(imsi,))['cx']==ims['cx']

def test_mobile_voice_ui_selects_aka_without_digest_aliases(ui_client):
    client,ui,module,d=ui_client;payload=bundle(d,'aka');imsi=payload['subscriber']['imsi']
    form={'profile':'mobile_voice_data','imsi':imsi,'msisdn':payload['subscriber']['msisdn'],'ki':payload['auc']['ki'],'opc':payload['auc']['opc'],'amf':'8000','internet_apn':'internet','ims_apn':'ims','sst':'1','sd':digits(6),'ue_ambr_ul':'1000000','ue_ambr_dl':'1000000','cx_realm':REALM,'cx_authentication':'aka'}
    response=client.post('/provision',data=form)
    assert 'failed' not in response.text.lower(),response.text
    ims=ui.one(ui.PYHSS_DB,'SELECT * FROM ims_subscriber WHERE imsi=?',(imsi,))
    assert ims['cx']['authentication_scheme']=='Digest-AKAv1-MD5'
    assert not ims['cx']['digest_identity_aliases']
    assert ui.one(ui.G5_DB,'SELECT * FROM udr_5g_slice WHERE imsi=?',(imsi,))

def test_guided_forms_have_no_subscriber_or_password_defaults(ui_client):
    client,ui,module,d=ui_client
    for kind in ('fixed_voice','mobile_voice_data'):
        text=client.get('/provision?profile='+kind).text
        for name in ('imsi','msisdn','digest_password','ki','opc'):
            import re
            match=re.search(r'<input[^>]*name="'+name+r'"[^>]*value="([^"]*)"',text)
            if match:assert match[1]==''

def test_ui_explicit_service_uris_require_tel_context_and_survive_edit(ui_client):
    client,ui,module,d=ui_client;imsi=digits(15);number=digits(11);service=digits(4)
    services=['sip:'+service+';phone-context='+REALM+'@'+REALM+';user=phone','tel:'+service+';phone-context='+REALM]
    form={'profile':'fixed_voice','imsi':imsi,'msisdn':'+'+number,'digest_password':'test-'+digits(16),'cx_realm':REALM,'ifc_path':'default_ifc.xml','cx_additional_public_identities':', '.join(services)}
    response=client.post('/provision',data=form);assert 'Native provisioning failed' not in response.text,response.text
    ims=ui.one(ui.PYHSS_DB,'SELECT * FROM ims_subscriber WHERE imsi=?',(imsi,));sid=ui.one(ui.PYHSS_DB,'SELECT * FROM subscriber WHERE imsi=?',(imsi,))['subscriber_id']
    page=client.get('/subscribers/'+str(sid)+'/edit').text
    assert all(identity in page for identity in services)
    response=client.post('/subscribers/'+str(sid)+'/edit',data={'msisdn':number,'cx_authentication':'sip_digest','cx_realm':REALM,'ifc_path':'default_ifc.xml','cx_additional_public_identities':', '.join(services)})
    assert response.status_code==303,response.text
    updated=module.cxProvisioning.get(ims['ims_subscriber_id'])
    assert all(identity in [item['identity'] for item in updated['cx']['public_identities']] for identity in services)
    form.update(imsi=digits(15),msisdn='+'+digits(11),cx_additional_public_identities='tel:'+service)
    response=client.post('/provision',data=form)
    assert 'requires phone-context' in response.text

def test_service_ui_edit_updates_cx_and_keeps_blank_credentials(ui_client):
    client,ui,module,d=ui_client;payload=bundle(d)
    saved=module.cxProvisioning.create_service(payload)
    sid=saved['subscriber']['subscriber_id'];iid=saved['ims_subscriber']['ims_subscriber_id'];replacement=digits(11)
    response=client.post('/subscribers/'+str(sid)+'/edit',data={'msisdn':replacement,'ue_ambr_ul':'1000000','ue_ambr_dl':'1000000','ifc_path':'default_ifc.xml','cx_authentication':'sip_digest','cx_realm':REALM,'ki':'','opc':'','amf':''})
    assert response.status_code==303,response.text
    ims=module.cxProvisioning.get(iid)
    assert ims['msisdn']==replacement
    assert 'sip:+'+replacement+'@'+REALM+';user=phone' in [x['identity'] for x in ims['cx']['public_identities']]
    from sqlalchemy import select
    from database import AUC
    with module.databaseClient.engine.connect() as c:assert c.scalar(select(AUC.ki).where(AUC.auc_id==saved['auc']['auc_id']))==payload['auc']['ki']

def test_untracked_explicit_global_identity_remains_visible_for_operator_review(ui_client):
    client,ui,module,d=ui_client;payload=bundle(d)
    extra='sip:+'+digits(11)+'@'+REALM+';user=phone'
    payload['ims_subscriber']['cx']['additional_public_identities']=[extra]
    saved=module.cxProvisioning.create_service(payload);profile=saved['ims_subscriber']['cx']
    profile.pop('provisioning')
    module.cxProvisioning.repo.provision(saved['ims_subscriber']['ims_subscriber_id'],profile,replace=True)
    page=client.get('/subscribers/'+str(saved['subscriber']['subscriber_id'])+'/edit').text
    assert extra in page

def test_ui_api_uses_discovered_endpoint_and_strict_mode_does_not_use_fixed_uri(ui_client,monkeypatch):
    from service_discovery import ServiceEndpoint
    client,ui,module,d=ui_client;seen=[]
    monkeypatch.setattr(ui,'_DISCOVERY_CONFIG',{'require_discovery':True,'services':{'PYHSS_API':{'domain':REALM,'srv':'_api._tcp.'+REALM}}})
    monkeypatch.setattr(ui.service_discovery,'resolve',lambda policy:ServiceEndpoint('api.'+REALM,54321,'tcp','http'))
    opener=ui._API_OPENER
    class Recording:
        def open(self,request,timeout=None):seen.append(request.full_url);return opener.open(request,timeout=timeout)
    monkeypatch.setattr(ui,'_API_OPENER',Recording())
    _,options=ui.api('GET','provisioning/options')
    assert options['authentication_methods'] and seen==['http://api.'+REALM+':54321/provisioning/options/']
    with pytest.raises(ui.DiscoveryError,match='required for PCF_URI'):ui.service_url('PCF_URI')

def test_ui_discovery_keeps_https_and_refuses_udp_for_http(ui_client,monkeypatch):
    from service_discovery import ServiceEndpoint
    client,ui,module,d=ui_client;seen=[]
    monkeypatch.setattr(ui,'PCF_URI','https://configured.'+REALM)
    monkeypatch.setattr(ui,'_DISCOVERY_CONFIG',{'services':{'PCF_URI':{'domain':REALM,'srv':'_pcf._tcp.'+REALM}}})
    def resolve(policy):seen.append(policy);return ServiceEndpoint('pcf.'+REALM,54321,'tcp',policy['scheme'])
    monkeypatch.setattr(ui.service_discovery,'resolve',resolve)
    assert ui.service_url('PCF_URI').startswith('https://') and seen[0]['scheme']=='https'
    monkeypatch.setattr(ui.service_discovery,'resolve',lambda policy:ServiceEndpoint('pcf.'+REALM,54321,'udp','https'))
    with pytest.raises(ui.DiscoveryError,match='TCP discovery'):ui.service_url('PCF_URI')
