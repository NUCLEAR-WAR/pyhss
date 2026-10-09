# Copyright 2026 PyHSS contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cx UAR/MAR/SAR/LIR procedures for provisioned distinct IMS user identities.

Procedure baseline: TS 29.228/29.229 V18.0.0. Provisioning, authentication
pending and successful registration are separate states. Optional restoration,
PSI, wildcard, NASS/GIBA and WebRTC features are not advertised by this module.
"""
from copy import deepcopy
import hashlib
import hmac
import json
from datetime import datetime,timezone
from sqlalchemy import select,update
from cx_repository import CxRepository,CxError,public_key,private_key
from milenage import Milenage

CX_APP=16777216
VENDOR=10415

class CxService:
    def __init__(self,diameter,config):
        self.d=diameter;self.repo=CxRepository(diameter.database,config)
        self.settings=config.get('hss',{}).get('cx',{})

    @staticmethod
    def values(avps,code,vendor=0):
        return [a for a in avps if a['avp_code']==code and (a.get('vendor_id') or 0)==vendor]

    def one(self,avps,code,vendor=0,required=True):
        found=self.values(avps,code,vendor)
        if not found:
            if required:raise CxError(5005,False,(code,vendor,''))
            return None
        if len(found)>1:raise CxError(5009,False,(code,vendor,found[-1].get('misc_data','')))
        return found[0]

    def text(self,avps,code,vendor=0,required=True):
        a=self.one(avps,code,vendor,required)
        if a is None:return None
        try:
            data=bytes.fromhex(a['misc_data']).decode('utf-8')
            if not data:raise ValueError()
            return data
        except (ValueError,TypeError,UnicodeError):raise CxError(5004,False,(code,vendor,a.get('misc_data','')))

    def integer(self,avps,code,vendor=VENDOR,default=None):
        a=self.one(avps,code,vendor,required=default is None)
        if a is None:return default
        try:
            data=bytes.fromhex(a['misc_data'])
            if len(data)!=4:raise ValueError()
            return int.from_bytes(data,'big')
        except (ValueError,TypeError):raise CxError(5004,False,(code,vendor,a.get('misc_data','')))

    def avp(self,code,value,vendor=0,integer=False):
        data=f'{value:08x}' if integer else bytes(value).hex() if isinstance(value,(bytes,bytearray,memoryview)) else str(value).encode().hex()
        return self.d.generate_vendor_avp(code,'c0',vendor,data) if vendor else self.d.generate_avp(code,'40',data)

    def grouped(self,code,payload,vendor=VENDOR):
        return self.d.generate_vendor_avp(code,'c0',vendor,payload) if vendor else self.d.generate_avp(code,'40',payload)

    def server(self,name):return self.avp(602,name,VENDOR)

    def capabilities(self):
        caps=self.settings.get('server_capabilities',{})
        children=''.join(self.avp(604,int(x),VENDOR,True) for x in caps.get('mandatory',[]))
        children+=''.join(self.avp(605,int(x),VENDOR,True) for x in caps.get('optional',[]))
        from service_discovery import hostname
        candidates=caps.get('server_names',self.repo.config.get('hss',{}).get('scscf_pool',[])) or []
        if not isinstance(candidates,list):raise ValueError('S-CSCF candidates must be a list')
        names=[]
        for candidate in candidates:
            if not isinstance(candidate,str):raise ValueError('S-CSCF candidate must be a DNS name')
            scheme='sips' if candidate.startswith('sips:') else 'sip'
            domain=candidate[len(scheme)+1:] if candidate.startswith(scheme+':') else candidate
            names.append(scheme+':'+hostname(domain))
        # These are candidates nested inside Server-Capabilities, not assignments.
        children+=''.join(self.server(name) for name in dict.fromkeys(names))
        return self.grouped(603,children) if children else ''

    def answer(self,packet,avps,code,payload='',experimental=False,failed=None):
        sid=self.values(avps,263)
        result=self.d.generate_avp(263,'40',sid[0]['misc_data']) if sid else ''
        result+=self.d.generate_avp(264,'40',self.d.OriginHost)+self.d.generate_avp(296,'40',self.d.OriginRealm)
        result+=self.avp(277,1,integer=True)
        result+=self.grouped(260,self.avp(266,VENDOR,integer=True)+self.avp(258,CX_APP,integer=True),vendor=0)
        if experimental:result+=self.grouped(297,self.avp(266,VENDOR,integer=True)+self.avp(298,code,integer=True),vendor=0)
        else:result+=self.avp(268,code,integer=True)
        result+=payload
        if failed:
            avp_code,vendor,data=failed
            if not data and avp_code in (277,607,614,623,624,633,637):data='00000000'
            child=self.d.generate_vendor_avp(avp_code,'c0',vendor,data) if vendor else self.d.generate_avp(avp_code,'40',data)
            result+=self.grouped(279,child,vendor=0)
        for proxy in self.values(avps,284):
            children=''.join(self.d.generate_avp(a['avp_code'],a['avp_flags'],a['misc_data']) for a in proxy.get('sub_avps',[]))
            result+=self.grouped(284,children,vendor=0)
        return self.d.generate_diameter_packet('01','40',packet['command_code'],CX_APP,
            packet['hop-by-hop-identifier'],packet['end-to-end-identifier'],result)

    def handle(self,packet,avps):
        try:
            self.text(avps,263);self.text(avps,264);self.text(avps,296);self.text(avps,283)
            self.one(avps,260)
            if self.integer(avps,277,vendor=0)!=1:raise CxError(5004,False,(277,0,self.one(avps,277)['misc_data']))
            method={300:self.uar,301:self.sar,302:self.lir,303:self.mar}[packet['command_code']]
            code,payload,experimental=method(avps)
            return self.answer(packet,avps,code,payload,experimental)
        except CxError as error:
            if error.reason:
                self.d.logTool.log(service='HSS',level='warning',
                    message=f'Cx {packet["command_code"]} rejected: {error.reason}; result={error.code}; experimental={error.experimental}',
                    redisClient=self.d.redisMessaging)
            return self.answer(packet,avps,error.code,self.server(error.server_name) if error.server_name else '',error.experimental,error.failed_avp)
        except Exception as error:
            # Backend/profile failures never become success or mutate partial state.
            self.d.logTool.log(service='HSS',level='error',message=f'Cx {packet["command_code"]} failed ({type(error).__name__})',redisClient=self.d.redisMessaging)
            return self.answer(packet,avps,5012)

    def authorize(self,profile,visited=None,emergency=False,registration=True):
        if emergency:return
        with self.repo.engine.connect() as c:
            sub=c.execute(select(self.repo.sub).where(self.repo.sub.c.imsi==profile['record']['imsi'])).mappings().first()
        if registration and (not sub or not sub.get('enabled',True)):raise CxError(5003,False)
        public=profile['public'];definition=profile['definition']
        if registration and not public.get('can_register',True):raise CxError(5003,False)
        if public['barred'] and not any(not p['barred'] for p in definition['public_identities'] if p['set_id']==public['set_id']):raise CxError(5003,False)
        if visited is not None:
            allowed=definition.get('visited_networks') or self.settings.get('visited_networks') or [definition['digest_realm']]
            # Visited-Network-Identifier is operator-coded OctetString; the lab
            # uses either the domain or its quoted P-Visited-Network-ID form.
            if visited not in allowed and not (visited.startswith('"') and visited.endswith('"') and visited[1:-1] in allowed):raise CxError(5004)

    def uar(self,avps):
        private=self.text(avps,1);public=self.text(avps,601,VENDOR);visited=self.text(avps,600,VENDOR)
        typ=self.integer(avps,623,default=0);flags=self.integer(avps,637,default=0)
        if typ not in (0,1,2):raise CxError(5004,False,(623,VENDOR,self.one(avps,623,VENDOR)['misc_data']))
        profile=self.repo.resolve(public,private,canonical_private=True)
        if typ!=1:self.authorize(profile,visited,bool(flags&1))
        else:self.authorize(profile,emergency=bool(flags&1),registration=False)
        with self.repo.engine.connect() as c:state=self.repo.state(profile,c)
        if typ==2:return 2001,self.capabilities(),False
        group=self.repo.group(state,profile['public']['set_id'])
        if typ==1:
            if state['scscf'] and (group['state'] in ('registered','unregistered') or profile['private'] in group['pending']):return 2001,self.server(state['scscf']),False
            raise CxError(5003)
        if state['scscf']:return 2002,self.server(state['scscf']),True
        return 2001,self.capabilities(),True

    def authentication_scheme(self,profile,requested):
        allowed=self.repo.authentication_schemes(profile)
        if requested in ('Unknown','unknown'):
            if 'SIP Digest' not in allowed:raise CxError(5006,reason='unknown_scheme_cannot_select_aka')
            return 'SIP Digest'
        if requested=='Digest-MD5' and self.settings.get('accept_legacy_digest_md5',False):requested='SIP Digest'
        if requested not in allowed or requested not in ('SIP Digest','Digest-AKAv1-MD5'):
            raise CxError(5006,reason='requested_authentication_scheme_mismatches_profile')
        return requested

    def mar(self,avps):
        private=self.text(avps,1);public=self.text(avps,601,VENDOR);server=self.text(avps,602,VENDOR)
        count=self.integer(avps,607)
        if count<1:raise CxError(5004,False,(607,VENDOR,self.one(avps,607,VENDOR)['misc_data']))
        item=self.one(avps,612,VENDOR);children=item.get('sub_avps',[]) or item.get('misc_data',[])
        if not isinstance(children,list):raise CxError(5004,False,(612,VENDOR,''))
        requested=self.text(children,608,VENDOR)
        token_avp=self.one(children,610,VENDOR,False)
        profile=self.repo.resolve(public,private);scheme=self.authentication_scheme(profile,requested)
        if scheme=='SIP Digest':
            canonical=profile['definition'].get('digest_identity_aliases',{}).get(profile['private'])
            if canonical:
                # Explicit operator-provisioned lookup alias, not a learned
                # association or a guess from IMSI/MSISDN. MAA identifies the
                # actual owner of the returned HA1, which Kamailio caches.
                profile=self.repo.resolve(public,canonical)
                self.authentication_scheme(profile,'SIP Digest')
                private=profile['private']
        self.authorize(profile)
        maximum=int(self.settings.get('max_auth_items',5))
        if maximum<1:raise ValueError('max_auth_items must be positive')
        count=min(count,maximum)
        if scheme=='SIP Digest':count=1  # TS 29.228 Table 6.3.4
        payload=self.avp(1,private)+self.avp(601,public,VENDOR);vectors=''
        with self.repo.transaction([profile['record']['ims_subscriber_id']]) as c:
            state=self.repo.state(profile,c);sub,auc=self.repo.credential(profile,c)
            if scheme=='SIP Digest':
                if token_avp:raise CxError(5004,False,(610,VENDOR,token_avp['misc_data']))
                realm=profile['definition']['digest_realm'];secret=auc['ki']
                ha1=hashlib.md5(f'{private}:{realm}:{secret}'.encode()).hexdigest()
                digest=self.grouped(635,self.avp(104,realm)+self.avp(111,'MD5')+self.avp(110,'auth')+self.avp(121,ha1))
                vectors=self.grouped(612,self.avp(608,'SIP Digest',VENDOR)+digest)
            else:
                key=bytes.fromhex(auc['ki']);opc=bytes.fromhex(auc['opc']);amf=bytes.fromhex(auc['amf'])
                if len(key)!=16 or len(opc)!=16 or len(amf)!=2:raise ValueError('Invalid provisioned AKA credentials')
                sqn=int(auc['sqn'] or 0)
                if token_avp:
                    token=bytes.fromhex(token_avp['misc_data'])
                    if len(token)!=30:raise CxError(5004,False,(610,VENDOR,token_avp['misc_data']))
                    if state['scscf']!=server:raise CxError(5012,False)
                    sqn_ms,mac=Milenage(b'\0\0').generate_resync(token[16:],key,opc,token[:16])
                    if not hmac.compare_digest(mac,token[-8:]):raise CxError(4001,False)
                    # Never roll back SQN on an old valid AUTS replay.
                    sqn=max(sqn,sqn_ms+1)
                if sqn<0 or sqn+count>0xffffffffffff:raise CxError(5012,False)
                mcc,mnc=self.repo.network_codes()
                plmn=bytes.fromhex(self.d.EncodePLMN(mcc,mnc))
                crypto=Milenage(amf)
                for number in range(count):
                    rand,xres,autn,ck,ik=crypto.generate_maa_vector(key,opc,sqn+number,plmn)
                    vectors+=self.grouped(612,self.avp(613,number,VENDOR,True)+self.avp(608,scheme,VENDOR)+
                        self.avp(609,rand+autn,VENDOR)+self.avp(610,xres,VENDOR)+self.avp(625,ck,VENDOR)+self.avp(626,ik,VENDOR))
                c.execute(update(self.repo.auc).where(self.repo.auc.c.auc_id==auc['auc_id']).values(sqn=sqn+count))
            group=deepcopy(self.repo.group(state,profile['public']['set_id']))
            if state['scscf']!=server:
                for current in state['groups'].values():current['known_private']=[]
                group['known_private']=[]
            if group['state']!='registered' or state['scscf']!=server:
                if profile['private'] not in group['pending']:group['pending'].append(profile['private'])
            state['groups'][profile['public']['set_id']]=group
            state.update(scscf=server,realm=self.text(avps,296),peer=self.text(avps,264)+';'+bytes.fromhex(self.d.OriginHost).decode())
            self.repo.save(state,c)
        return 2001,payload+self.avp(607,count,VENDOR,True)+vectors,False

    def sar(self,avps):
        typ=self.integer(avps,614);available=self.integer(avps,624)
        if typ not in range(12):raise CxError(5007)
        if available not in (0,1):raise CxError(5004,False,(624,VENDOR,self.one(avps,624,VENDOR)['misc_data']))
        private=self.text(avps,1,required=False);server=self.text(avps,602,VENDOR)
        public_avps=self.values(avps,601,VENDOR)
        if typ in (0,1,2,3,5,7,9,10) and len(public_avps)!=1:
            raise CxError(5009 if len(public_avps)>1 else 5005,False,(601,VENDOR,''))
        if typ in (1,2,9,10) and private is None:raise CxError(5005,False,(1,0,''))
        publics=[bytes.fromhex(a['misc_data']).decode() for a in public_avps]
        if not publics:
            if not private:raise CxError(5005,False,(1,0,''))
            with self.repo.engine.connect() as c:
                _,definition=self.repo.find(private,'private',c)
            publics=[p['identity'] for p in definition['public_identities'] if private_key(private) in p['private_identities']]
        profiles=[self.repo.resolve(p,private) for p in publics]
        if private and any(private_key(private) in p['definition'].get('digest_identity_aliases',{}) for p in profiles):
            # MAA identifies the real authentication IMPI. A bootstrap lookup
            # name must not become a successful registration's private identity.
            raise CxError(5002)
        # Optional restoration/wildcard features are not negotiated or silently applied.
        if self.values(avps,634,VENDOR) or self.values(avps,639,VENDOR) or self.integer(avps,655,default=0):raise CxError(5011)
        payload='';code=2001;experimental=False
        if typ in (0,1,2,3) and not available:
            profile=profiles[0];chosen=private or self.repo.default_authentication_identity(profile)
            payload=self.avp(1,chosen)+self.avp(606,self.repo.user_data(profile,chosen),VENDOR)
            real_private=[identity for identity in profile['definition']['private_identities'] if identity not in profile['definition'].get('digest_identity_aliases',{})]
            if len(real_private)>1:
                payload+=self.grouped(632,''.join(self.avp(1,x) for x in real_private))
        with self.repo.transaction([p['record']['ims_subscriber_id'] for p in profiles]) as c:
            states={};seen=set()
            for profile in profiles:
                ident=profile['record']['ims_subscriber_id'];set_id=profile['public']['set_id']
                if (ident,set_id) in seen:continue
                seen.add((ident,set_id))
                state=states.setdefault(ident,self.repo.state(profile,c));group=deepcopy(self.repo.group(state,set_id))
                if typ==0:
                    if state['scscf']!=server:raise CxError(5012,False)
                    continue
                if state['scscf'] and state['scscf']!=server:raise CxError(5005,server_name=state['scscf'])
                if typ in (1,2):
                    private=profile['private'];group['state']='registered'
                    if private not in group['registered']:group['registered'].append(private)
                    group['pending']=[p for p in group['pending'] if p!=private]
                    known=group.setdefault('known_private',[])
                    if private not in known:known.append(private)
                    state.update(scscf=server,realm=self.text(avps,296),peer=self.text(avps,264)+';'+bytes.fromhex(self.d.OriginHost).decode())
                elif typ==3:
                    chosen=private or self.repo.default_authentication_identity(profile)
                    group={'state':'unregistered','registered':[],'pending':[],'known_private':[chosen]}
                    state.update(scscf=server,realm=self.text(avps,296),peer=self.text(avps,264)+';'+bytes.fromhex(self.d.OriginHost).decode())
                elif typ in (9,10):
                    group['pending']=[p for p in group['pending'] if p!=profile['private']]
                else:
                    if private is None and len(group['registered'])>1:raise CxError(5005,False,(1,0,''))
                    had_service_assignment=group['state'] in ('registered','unregistered')
                    group['registered']=[p for p in group['registered'] if private and p!=private_key(private)]
                    group['pending']=[p for p in group['pending'] if private and p!=private_key(private)]
                    keep=typ in (6,7) and self.settings.get('store_server_on_deregistration',True)
                    if group['registered']:group['state']='registered'
                    elif keep:group['state']='unregistered'
                    else:
                        group['state']='not_registered'
                        if had_service_assignment:
                            # TS 29.228 6.1.2: removing the last registration
                            # without STORE_SERVER_NAME releases this set's
                            # assignment. Incomplete authentication for a
                            # bootstrap/other IMPI in the same set cannot pin it.
                            group['pending']=[]
                            group['known_private']=[]
                    if typ in (6,7) and not keep:code=2004;experimental=True
                state['groups'][set_id]=group
                if not any(g['state'] in ('registered','unregistered') or g['pending'] for g in state['groups'].values()):
                    state.update(scscf=None,realm=None,peer=None)
            if typ!=0:
                for state in states.values():self.repo.save(state,c)
        return code,payload,experimental

    def lir(self,avps):
        public=self.text(avps,601,VENDOR);originating_avp=self.one(avps,633,VENDOR,False)
        originating=originating_avp is not None
        if originating and self.integer(avps,633)!=0:
            raise CxError(5004,False,(633,VENDOR,originating_avp['misc_data']))
        profile=self.repo.resolve(public)
        with self.repo.engine.connect() as c:state=self.repo.state(profile,c)
        group=self.repo.group(state,profile['public']['set_id'])
        if group['state'] in ('registered','unregistered') and state['scscf']:return 2001,self.server(state['scscf']),False
        if originating or self.repo.terminating_unregistered_service(profile):
            if state['scscf']:return 2001,self.server(state['scscf']),False
            return 2003,self.capabilities(),True
        raise CxError(5003,reason='terminating_unregistered_service_not_available')

    def rtr(self, imsi, destination_host, destination_realm, registration_sets=None):
        """Build a Cx RTR for active implicit registration sets.

        Public-Identity AVP 601 is mandatory for our Kamailio S-CSCF. Only
        provisioned identities belonging to the selected active IRS are sent.
        Never derive public identities from an IMSI or incoming SIP URI.
        """
        with self.repo.engine.connect() as connection:
            records = connection.execute(
                select(self.repo.ims).where(self.repo.ims.c.imsi == imsi)
            ).mappings().all()
            if len(records) != 1:
                raise CxError(5001)
            record = dict(records[0])
            definition = self.repo.definition(record, connection)
            state = self.repo.state({'record': record, 'definition': definition}, connection)
            active = {name: group for name, group in (state.get('groups') or {}).items()
                      if group.get('registered')}
            selected = list(registration_sets) if registration_sets is not None else list(active)
            if not selected or any(name not in active for name in selected):
                raise ValueError('RTR requires explicitly registered IRS groups')
            public = []
            for identity in definition['public_identities']:
                if identity['set_id'] in selected and identity['identity'] not in public:
                    public.append(identity['identity'])
            if not public:
                raise ValueError('RTR has no provisioned public identities in active IRS')
            known = []
            for name in selected:
                group = active[name]
                for identity in group.get('registered', []):
                    if identity not in known:
                        known.append(identity)
            if not known:
                raise ValueError('RTR has no registered private identity')
            aliases = definition.get('digest_identity_aliases', {})
            target = aliases.get(known[0], known[0])
            if target not in definition['private_identities']:
                raise ValueError('Registered IMPI is not provisioned in this Cx profile')
        sid = bytes.fromhex(self.d.OriginHost).decode() + ';cx-rtr;' + __import__('uuid').uuid4().hex
        payload = self.avp(263, sid)
        payload += self.d.generate_avp(264, '40', self.d.OriginHost)
        payload += self.d.generate_avp(296, '40', self.d.OriginRealm)
        payload += self.grouped(260, self.avp(266, VENDOR, integer=True)
                                + self.avp(258, CX_APP, integer=True), vendor=0)
        payload += self.avp(277, 1, integer=True)
        payload += self.avp(293, destination_host) + self.avp(283, destination_realm)
        payload += self.avp(1, target)
        payload += self.grouped(615, self.avp(616, 0, VENDOR, True)
                                + self.avp(617, 'Administrative de-registration', VENDOR))
        for impu in public:
            payload += self.avp(601, impu, VENDOR)
        return self.d.generate_diameter_packet('01', 'c0', 304, CX_APP,
                                               self.d.generate_id(4), self.d.generate_id(4), payload)

