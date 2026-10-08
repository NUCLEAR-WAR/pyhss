# Copyright 2026 PyHSS contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Provisioned Cx identities and registration state in the native PyHSS DB.

Identity provisioning is separate from registration. No UAR/MAR/SAR handler
inserts a private/public identity association. Legacy IFCs remain a read-only
source of provisioned identities until explicit profiles are provisioned.
"""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import json
import xml.etree.ElementTree as ET
import jinja2
from sqlalchemy import (MetaData,Table,Column,Integer,String,Text,DateTime,
                        ForeignKey,select,update,delete,inspect)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.dialects.mysql import VARCHAR
import time

class CxError(Exception):
    def __init__(self,code,experimental=True,failed_avp=None,server_name=None,reason=None):
        self.code=code;self.experimental=experimental;self.failed_avp=failed_avp
        self.server_name=server_name;self.reason=reason
        super().__init__(f'Cx result {code}')

def public_key(identity):
    """Preserve user/number and URI parameters; normalize scheme and SIP host."""
    if not isinstance(identity,str) or identity!=identity.strip() or any(c.isspace() for c in identity):
        raise ValueError('Invalid provisioned public identity')
    scheme,sep,rest=identity.partition(':')
    if not sep or scheme.lower() not in ('sip','sips','tel') or not rest:raise ValueError('Invalid public URI')
    if scheme.lower() in ('sip','sips'):
        user,at,host=rest.partition('@')
        if not at or not user or not host:raise ValueError('Public SIP identity requires user and host')
        hostpart,semi,params=host.partition(';')
        rest=user+'@'+hostpart.lower()+(semi+params if semi else '')
    return scheme.lower()+':'+rest

def private_key(identity):
    if not isinstance(identity,str) or identity!=identity.strip() or any(c.isspace() for c in identity):
        raise ValueError('Invalid provisioned private identity')
    user,at,realm=identity.rpartition('@')
    if not at or not user or not realm or ':' in user:raise ValueError('Private identity must be a full NAI')
    return user+'@'+realm.lower()

class CxRepository:
    def __init__(self,database,config,root=None,initialize_schema=True):
        from database import IMS_SUBSCRIBER,SUBSCRIBER,AUC
        self.db=database;self.engine=database.engine;self.config=config
        self.settings=config.get('hss',{}).get('cx',{})
        self.ims=IMS_SUBSCRIBER.__table__;self.sub=SUBSCRIBER.__table__;self.auc=AUC.__table__
        self.root=Path(root or Path(__file__).resolve().parents[1])
        self.metadata=MetaData()
        self.profiles=Table('ims_cx_profile',self.metadata,
            Column('ims_subscriber_id',Integer,ForeignKey(self.ims.c.ims_subscriber_id,ondelete='CASCADE'),primary_key=True),
            Column('definition',Text,nullable=False))
        self.identities=Table('ims_cx_identity',self.metadata,
            Column('identity',String(512).with_variant(VARCHAR(512,collation='utf8mb4_bin'),'mysql'),primary_key=True),Column('kind',String(8),primary_key=True),
            Column('ims_subscriber_id',Integer,ForeignKey(self.profiles.c.ims_subscriber_id,ondelete='CASCADE'),nullable=False),mysql_charset='utf8mb4')
        self.states=Table('ims_cx_state',self.metadata,
            Column('ims_subscriber_id',Integer,ForeignKey(self.ims.c.ims_subscriber_id,ondelete='CASCADE'),primary_key=True),
            Column('scscf',String(512)),Column('realm',String(255)),Column('peer',String(512)),
            Column('groups_json',Text,nullable=False),Column('registered_at',DateTime),
            Column('updated_at',DateTime,nullable=False))
        if not initialize_schema:return
        # Startup-only additive DDL, never a migration of provisioned identities.
        for attempt in range(4):
            try:
                self.metadata.create_all(self.engine);break
            except SQLAlchemyError as error:
                # Retry only an actual sibling startup's duplicate-table race;
                # permission, connection and incompatible-schema errors still fail.
                original=getattr(error,'orig',None)
                duplicate=(getattr(original,'pgcode',None)=='42P07' or
                    getattr(original,'args',(None,))[0]==1050 or 'already exists' in str(original).lower())
                if not duplicate or attempt==3:raise
                time.sleep(0.05)

    @contextmanager
    def transaction(self,profile_ids=()):
        with self.engine.connect() as c:
            if c.dialect.name=='sqlite':c.exec_driver_sql('BEGIN IMMEDIATE')
            else:c.begin()
            try:
                for ident in sorted(set(profile_ids)):
                    # Lock an existing parent even before its first runtime row exists.
                    c.execute(select(self.ims.c.ims_subscriber_id).where(self.ims.c.ims_subscriber_id==ident).with_for_update()).first()
                yield c
                c.commit()
            except BaseException:
                c.rollback();raise

    def record(self,ident,c):
        row=c.execute(select(self.ims).where(self.ims.c.ims_subscriber_id==ident)).mappings().first()
        if row is None:raise CxError(5001,reason='ims_subscription_not_found')
        return dict(row)

    def network_codes(self):
        """Require the operator's configured PLMN; never guess a lab network."""
        hss=self.config.get('hss',{})
        mcc=str(hss.get('MCC',''));mnc=str(hss.get('MNC',''))
        if len(mcc)!=3 or not mcc.isascii() or not mcc.isdigit():
            raise ValueError('Configure hss.MCC as a three-digit string')
        if len(mnc) not in (2,3) or not mnc.isascii() or not mnc.isdigit():
            raise ValueError('Configure hss.MNC as a two- or three-digit string')
        return mcc,mnc

    def xml(self,record):
        path=record.get('ifc_path') or 'default_ifc.xml'
        loaders=[str(self.root),str(self.root/'templates'),str(Path.cwd().parent)]
        if Path(path).is_absolute():loaders.insert(0,str(Path(path).parent));path=Path(path).name
        env=jinja2.Environment(loader=jinja2.FileSystemLoader(loaders),autoescape=True)
        values=dict(record);mcc,mnc=self.network_codes()
        values.update(mcc=mcc,mnc=mnc.zfill(3))
        return ET.fromstring(env.get_template(path).render(iFC_vars=values))

    def legacy_profile(self,record):
        root=self.xml(record);private=root.findtext('PrivateID')
        if not private:raise ValueError('IFC must contain a provisioned PrivateID')
        public=[]
        for element in root.findall('./ServiceProfile/PublicIdentity'):
            identity=element.findtext('Identity')
            if identity:public.append({'identity':identity,'set_id':'default','barred':element.findtext('BarringIndication','0')=='1'})
        return {'private_identities':[private],'public_identities':public,
                'authentication_scheme':'Digest-AKAv1-MD5','digest_realm':private.rpartition('@')[2],
                'unregistered_service':False}

    def definition(self,record,c):
        row=c.execute(select(self.profiles.c.definition).where(self.profiles.c.ims_subscriber_id==record['ims_subscriber_id'])).first()
        return self.validate_definition(json.loads(row[0]) if row else self.legacy_profile(record))

    @staticmethod
    def validate_definition(definition):
        d=deepcopy(definition)
        d['private_identities']=[private_key(x) for x in d['private_identities']]
        if not d['private_identities'] or len(set(d['private_identities']))!=len(d['private_identities']):raise ValueError('Duplicate/empty private identities')
        for item in d['public_identities']:
            item['identity']=public_key(item['identity']);item.setdefault('set_id','default');item.setdefault('barred',False)
            if not isinstance(item['set_id'],str) or not 1<=len(item['set_id'])<=64:raise ValueError('Invalid implicit registration set')
            item.setdefault('private_identities',d['private_identities'])
            item['private_identities']=[private_key(x) for x in item['private_identities']]
            if not item['private_identities'] or not set(item['private_identities'])<=set(d['private_identities']):raise ValueError('Invalid provisioned identity association')
            if type(item['barred']) is not bool or type(item.get('can_register',True)) is not bool:raise ValueError('Identity policy flags must be booleans')
        ids=[x['identity'] for x in d['public_identities']]
        if not ids or len(ids)!=len(set(ids)):raise ValueError('Duplicate/empty public identities')
        sets={}
        for item in d['public_identities']:
            associations=set(item['private_identities'])
            if sets.setdefault(item['set_id'],associations)!=associations:raise ValueError('Implicitly registered identities must have consistent private associations')
        d.setdefault('authentication_scheme','Digest-AKAv1-MD5')
        if d['authentication_scheme'] not in ('Digest-AKAv1-MD5','SIP Digest'):raise ValueError('Unsupported provisioned authentication scheme')
        schemes=d.get('authentication_schemes',{})
        if not isinstance(schemes,dict):raise ValueError('authentication_schemes must map private identities to schemes')
        d['authentication_schemes']={private_key(identity):scheme for identity,scheme in schemes.items()}
        if not set(d['authentication_schemes'])<=set(d['private_identities']):raise ValueError('Authentication policy references an unprovisioned private identity')
        for schemes in d['authentication_schemes'].values():
            allowed=[schemes] if isinstance(schemes,str) else schemes
            if not isinstance(allowed,list) or not allowed or len(allowed)!=len(set(allowed)):
                raise ValueError('Private authentication policy must contain distinct scheme names')
            if any(scheme not in ('Digest-AKAv1-MD5','SIP Digest') for scheme in allowed):
                raise ValueError('Unsupported private identity authentication scheme')
        d.setdefault('digest_realm',d['private_identities'][0].rpartition('@')[2])
        if not isinstance(d['digest_realm'],str) or not d['digest_realm']:raise ValueError('Digest realm must be provisioned')
        d.setdefault('unregistered_service',False)
        return d

    @staticmethod
    def authentication_scheme(profile):
        return CxRepository.authentication_schemes(profile)[0]

    @staticmethod
    def authentication_schemes(profile):
        definition=profile['definition']
        value=definition.get('authentication_schemes',{}).get(profile.get('private'),definition['authentication_scheme'])
        return [value] if isinstance(value,str) else list(value)

    def provision(self,profile_id,definition,replace=False):
        d=self.validate_definition(definition)
        with self.transaction([profile_id]) as c:
            record=self.record(profile_id,c)
            present=c.execute(select(self.profiles).where(self.profiles.c.ims_subscriber_id==profile_id)).first()
            if present and not replace:raise ValueError('Cx profile exists; use explicit replacement')
            state=c.execute(select(self.states).where(self.states.c.ims_subscriber_id==profile_id)).mappings().first()
            if state and state['scscf']:raise ValueError('De-register before changing the provisioned Cx profile')
            if not state and record.get('scscf') and record.get('scscf_timestamp'):raise ValueError('De-register the legacy active subscription before changing its Cx profile')
            for kind,identities in [('private',d['private_identities']),('public',[p['identity'] for p in d['public_identities']])]:
                for identity in identities:
                    other=c.execute(select(self.identities.c.ims_subscriber_id).where(self.identities.c.identity==identity,self.identities.c.kind==kind)).first()
                    if other and other[0]!=profile_id:raise ValueError('Identity already provisioned under another subscription')
            c.execute(delete(self.identities).where(self.identities.c.ims_subscriber_id==profile_id))
            if present:c.execute(update(self.profiles).where(self.profiles.c.ims_subscriber_id==profile_id).values(definition=json.dumps(d)))
            else:c.execute(self.profiles.insert().values(ims_subscriber_id=profile_id,definition=json.dumps(d)))
            for kind,values in [('private',d['private_identities']),('public',[p['identity'] for p in d['public_identities']])]:
                c.execute(self.identities.insert(),[{'identity':i,'kind':kind,'ims_subscriber_id':profile_id} for i in values])
        return d

    def find(self,identity,kind,c):
        try:key=private_key(identity) if kind=='private' else public_key(identity)
        except ValueError:raise CxError(5001,reason='invalid_'+kind+'_identity_format')
        explicit=c.execute(select(self.identities.c.ims_subscriber_id).where(self.identities.c.identity==key,self.identities.c.kind==kind)).first()
        if explicit:
            record=self.record(explicit[0],c);return record,self.definition(record,c)
        matches=[]
        # Legacy transition: use provisioned XML, not numeric length or a request's realm.
        records=c.execute(select(self.ims)).mappings().all()
        for row in records:
            record=dict(row)
            if c.execute(select(self.profiles.c.ims_subscriber_id).where(self.profiles.c.ims_subscriber_id==record['ims_subscriber_id'])).first():continue
            try:d=self.validate_definition(self.legacy_profile(record))
            except (ValueError,ET.ParseError,jinja2.TemplateError):continue
            values=d['private_identities'] if kind=='private' else [p['identity'] for p in d['public_identities']]
            if key in values:matches.append((record,d))
        if not matches:raise CxError(5001,reason=kind+'_identity_not_provisioned')
        if len(matches)!=1:raise CxError(5012,False)
        return matches[0]

    def resolve(self,public,private=None,c=None):
        if c is None:
            with self.engine.connect() as conn:return self.resolve(public,private,conn)
        record,d=self.find(public,'public',c)
        item=next(x for x in d['public_identities'] if x['identity']==public_key(public))
        if private is not None:
            private_record,_=self.find(private,'private',c)
            if private_record['ims_subscriber_id']!=record['ims_subscriber_id'] or private_key(private) not in item['private_identities']:raise CxError(5002)
        return {'record':record,'definition':d,'public':item,'private':private_key(private) if private else None}

    def state(self,profile,c):
        ident=profile['record']['ims_subscriber_id']
        row=c.execute(select(self.states).where(self.states.c.ims_subscriber_id==ident)).mappings().first()
        if row:
            value=dict(row);value['groups']=json.loads(value.pop('groups_json'));return value
        record=profile['record'];registered=bool(record.get('scscf') and record.get('scscf_timestamp'))
        groups={}
        if registered:
            for public in profile['definition']['public_identities']:
                groups[public['set_id']]={'state':'registered','registered':list(public['private_identities']),'pending':[]}
        # scscf without a registration timestamp is a legacy provisioning hint,
        # not proof of an assignment. Never learn state from an initial UAR.
        return {'ims_subscriber_id':ident,'scscf':record.get('scscf') if registered else None,
                'realm':record.get('scscf_realm') if registered else None,
                'peer':record.get('scscf_peer') if registered else None,
                'registered_at':record.get('scscf_timestamp') if registered else None,'groups':groups}

    @staticmethod
    def group(state,set_id):
        return state['groups'].get(set_id,{'state':'not_registered','registered':[],'pending':[]})

    def save(self,state,c):
        state=deepcopy(state);ident=state['ims_subscriber_id'];now=datetime.now(timezone.utc).replace(tzinfo=None)
        groups=state.pop('groups');state.update(groups_json=json.dumps(groups),updated_at=now)
        registered=any(g['registered'] for g in groups.values())
        if not registered:state['registered_at']=None
        elif not state.get('registered_at'):state['registered_at']=now
        if c.execute(select(self.states.c.ims_subscriber_id).where(self.states.c.ims_subscriber_id==ident)).first():
            c.execute(update(self.states).where(self.states.c.ims_subscriber_id==ident).values(**state))
        else:c.execute(self.states.insert().values(**state))
        # Keep existing Admin/statistics/API consumers synchronized. Pending
        # authentication stores routing but never stamps a successful registration.
        c.execute(update(self.ims).where(self.ims.c.ims_subscriber_id==ident).values(
            scscf=state['scscf'],scscf_realm=state['realm'],scscf_peer=state['peer'],scscf_timestamp=state['registered_at']))

    def credential(self,profile,c):
        subscriber=c.execute(select(self.sub).where(self.sub.c.imsi==profile['record']['imsi'])).mappings().first()
        if not subscriber:raise CxError(5001,reason='native_subscriber_not_found')
        auc=c.execute(select(self.auc).where(self.auc.c.auc_id==subscriber['auc_id']).with_for_update()).mappings().first()
        if not auc:raise CxError(5001,reason='native_auc_not_found')
        return dict(subscriber),dict(auc)

    def user_data(self,profile,private=None):
        root=self.xml(profile['record']);d=profile['definition'];set_id=profile['public']['set_id']
        private=private or d['private_identities'][0]
        if root.find('PrivateID') is None:ET.SubElement(root,'PrivateID')
        root.find('PrivateID').text=private
        wanted=[x for x in d['public_identities'] if x['set_id']==set_id]
        by_key={x['identity']:x for x in wanted};seen=set()
        service_profiles=root.findall('ServiceProfile')
        if not service_profiles:service_profiles=[ET.SubElement(root,'ServiceProfile')]
        for sp in service_profiles:
            for element in list(sp.findall('PublicIdentity')):
                try:key=public_key(element.findtext('Identity',''))
                except ValueError:key=''
                if key not in by_key:sp.remove(element);continue
                seen.add(key);bar=element.find('BarringIndication')
                if bar is None:bar=ET.Element('BarringIndication');element.insert(0,bar)
                bar.text='1' if by_key[key]['barred'] else '0'
        for item in wanted:
            if item['identity'] in seen:continue
            element=ET.Element('PublicIdentity')
            # TS 29.228 Annex A: PublicIdentity precedes InitialFilterCriteria.
            service_profiles[0].insert(len(service_profiles[0].findall('PublicIdentity')),element)
            ET.SubElement(element,'BarringIndication').text='1' if item['barred'] else '0'
            ET.SubElement(element,'Identity').text=item['identity']
        for sp in service_profiles:
            if not sp.findall('PublicIdentity'):root.remove(sp)
        return ET.tostring(root,encoding='unicode')
