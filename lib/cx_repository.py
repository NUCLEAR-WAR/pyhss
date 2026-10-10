# Copyright 2026 PyHSS contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Provisioned Cx identities and registration state in the native PyHSS DB.

Identity provisioning is separate from registration. No UAR/MAR/SAR handler
inserts a private/public identity association. Legacy IFCs remain a read-only
source of provisioned identities until explicit profiles are provisioned.
"""
from contextlib import contextmanager,nullcontext
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import json,re
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

def validate_provisioned_public_uri(identity,private_derived=False):
    """Validate new TEL provisioning without invalidating legacy reads.

    SIP service users need no plus. Local TEL numbers require an explicit
    phone-context; global TEL numbers start with plus (RFC 3966 section 5.1).
    """
    identity=public_key(identity)
    if identity.startswith(('sip:','sips:')):
        user,_,host=identity.partition(':')[2].partition('@')
        number,*user_parameters=user.split(';')
        uri_parameters=host.split(';')[1:]
        users=[p.partition('=')[2].lower() for p in uri_parameters if p.partition('=')[0].lower()=='user']
        if len(users)>1:raise ValueError('SIP identity has duplicate user parameter: '+identity)
        if any(p.partition('=')[0].lower()=='phone-context' for p in uri_parameters):
            raise ValueError('SIP telephone phone-context must precede @: '+identity)
        phone_context=any(p.partition('=')[0].lower()=='phone-context' for p in user_parameters)
        if users==['phone']:
            validate_provisioned_public_uri('tel:'+user)
        # Bare SIP userinfo is provisioned as supplied, not rewritten into a
        # telephone URI. An explicit user=phone URI still needs valid TEL form.
        return identity
    if not identity.startswith('tel:'):return identity
    number,*parameters=identity[4:].split(';')
    global_number=number.startswith('+')
    digits=number[1:] if global_number else number
    pattern=r'[0-9().-]*[0-9][0-9().-]*' if global_number else r'[0-9A-Fa-f*#().-]*[0-9A-Fa-f*#][0-9A-Fa-f*#().-]*'
    if not re.fullmatch(pattern,digits):raise ValueError('Invalid TEL telephone number: '+identity)
    contexts=[parameter.partition('=')[2] for parameter in parameters if parameter.partition('=')[0].lower()=='phone-context']
    if not global_number and not contexts:raise ValueError('Local TEL public identity requires phone-context: '+identity)
    if len(contexts)>1:raise ValueError('TEL public identity has duplicate phone-context: '+identity)
    if contexts:
        context=contexts[0]
        if context.startswith('+'):
            valid=re.fullmatch(r'\+[0-9().-]*[0-9][0-9().-]*',context)
        else:
            valid=re.fullmatch(r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?',context)
        if not valid:raise ValueError('Invalid TEL phone-context: '+identity)
    return identity

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
        self.live_ifc=Table('ims_cx_live_ifc',self.metadata,
            Column('ims_subscriber_id',Integer,ForeignKey(self.ims.c.ims_subscriber_id,ondelete='CASCADE'),primary_key=True),
            Column('set_id',String(255),primary_key=True),
            Column('version',Integer,nullable=False),
            Column('ifc_xml',Text,nullable=False),
            Column('updated_at',DateTime,nullable=False))
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

    @staticmethod
    def ifc_has_terminating_unregistered_service(root):
        """Could an active iFC apply to INVITE / TERMINATING_UNREGISTERED?

        Method/session case are known. Header/URI/SDP conditions may match a
        call and are treated as possible, respecting the iFC CNF/DNF groups.
        This discovers provisioned service eligibility, not an S-CSCF trigger.
        """
        def boolean(value):
            if value in ('0','false'):return False
            if value in ('1','true'):return True
            raise ValueError('Invalid IFC boolean')
        for rule in root.findall('./ServiceProfile/InitialFilterCriteria'):
            if rule.findtext('ProfilePartIndicator')=='0':continue
            if not rule.findtext('./ApplicationServer/ServerName'):continue
            trigger=rule.find('TriggerPoint')
            if trigger is None:return True
            cnf=boolean(trigger.findtext('ConditionTypeCNF','0'))
            groups={}
            for item in trigger.findall('SPT'):
                value=None
                if item.find('Method') is not None:value=item.findtext('Method')=='INVITE'
                elif item.find('SessionCase') is not None:value=item.findtext('SessionCase')=='2'
                if boolean(item.findtext('ConditionNegated','0')) and value is not None:value=not value
                members=item.findall('Group')
                if not members:raise ValueError('IFC SPT requires a group')
                for group in members:groups.setdefault(group.text,[]).append(value)
            if not groups:continue
            # Unknown predicates can match; impossible known predicates cannot.
            possible=[any(value is not False for value in values) if cnf else all(value is not False for value in values)
                for values in groups.values()]
            if (all(possible) if cnf else any(possible)):return True
        return False

    @staticmethod
    def unregistered_service_policy(definition):
        mode=definition.get('unregistered_service_policy')
        if mode is not None:
            if mode not in ('auto','enabled','disabled'):raise ValueError('Invalid unregistered service policy')
            return mode
        # The older auto-provisioner always wrote false without reading IFC.
        # Only those identifiable generated profiles inherit the IFC default.
        if definition.get('provisioning') and not definition.get('unregistered_service',False):return 'auto'
        return 'enabled' if definition.get('unregistered_service',False) else 'disabled'

    def terminating_unregistered_service(self,profile):
        mode=self.unregistered_service_policy(profile['definition'])
        if mode!='auto':return mode=='enabled'
        return self.ifc_has_terminating_unregistered_service(ET.fromstring(self.user_data(profile)))

    def legacy_profile(self,record):
        root=self.xml(record);private=root.findtext('PrivateID')
        if not private:raise ValueError('IFC must contain a provisioned PrivateID')
        public=[]
        for element in root.findall('./ServiceProfile/PublicIdentity'):
            identity=element.findtext('Identity')
            if identity:public.append({'identity':identity,'set_id':'default','barred':element.findtext('BarringIndication','0')=='1'})
        return {'private_identities':[private],'public_identities':public,
                'authentication_scheme':'Digest-AKAv1-MD5','digest_realm':private.rpartition('@')[2],
                'unregistered_service':self.ifc_has_terminating_unregistered_service(root),
                'unregistered_service_policy':'auto'}

    def definition(self,record,c):
        row=c.execute(select(self.profiles.c.definition).where(self.profiles.c.ims_subscriber_id==record['ims_subscriber_id'])).first()
        return self.validate_definition(json.loads(row[0]) if row else self.legacy_profile(record))

    @staticmethod
    def validate_definition(definition,allow_partial_sets=False):
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
        # Preserve the fork's barring rule: an implicit set must remain usable.
        for set_id in sets:
            if not allow_partial_sets and not any(not item['barred'] for item in d['public_identities'] if item['set_id']==set_id):
                raise ValueError('Implicit registration set has no non-barred public identity: '+set_id)
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
        aliases=d.get('digest_identity_aliases',{})
        if not isinstance(aliases,dict):raise ValueError('digest_identity_aliases must map lookup identities to authentication identities')
        d['digest_identity_aliases']={private_key(source):private_key(target) for source,target in aliases.items()}
        for source,target in d['digest_identity_aliases'].items():
            if source==target or source not in d['private_identities'] or target not in d['private_identities']:
                raise ValueError('Digest aliases must reference distinct provisioned private identities')
            if target in d['digest_identity_aliases']:raise ValueError('Chained or cyclic Digest identity aliases are not supported')
            for identity in (source,target):
                schemes=d['authentication_schemes'].get(identity,d['authentication_scheme'])
                if 'SIP Digest' not in ([schemes] if isinstance(schemes,str) else schemes):
                    raise ValueError('Both Digest alias identities must explicitly allow SIP Digest')
            for public in d['public_identities']:
                if source in public['private_identities'] and target not in public['private_identities']:
                    raise ValueError('Digest alias target must be associated with every public identity served by its lookup alias')
        d.setdefault('digest_realm',d['private_identities'][0].rpartition('@')[2])
        if not isinstance(d['digest_realm'],str) or not d['digest_realm']:raise ValueError('Digest realm must be provisioned')
        d.setdefault('unregistered_service',False)
        if type(d['unregistered_service']) is not bool:raise ValueError('unregistered_service must be a boolean')
        if 'unregistered_service_policy' in d and d['unregistered_service_policy'] not in ('auto','enabled','disabled'):
            raise ValueError('Invalid unregistered service policy')
        CxRepository.unregistered_service_policy(d)
        return d

    @staticmethod
    def default_authentication_identity(profile):
        aliases=profile['definition'].get('digest_identity_aliases',{})
        return next(identity for identity in profile['public']['private_identities'] if identity not in aliases)

    @staticmethod
    def authentication_scheme(profile):
        return CxRepository.authentication_schemes(profile)[0]

    @staticmethod
    def authentication_schemes(profile):
        if profile.get('private') in profile['definition'].get('digest_identity_aliases',{}):return ['SIP Digest']
        definition=profile['definition']
        value=definition.get('authentication_schemes',{}).get(profile.get('private'),definition['authentication_scheme'])
        return [value] if isinstance(value,str) else list(value)

    def prepare_definition(self,record,definition,allow_partial_sets=False):
        # Missing flags inherit rendered IFC barring. Explicit booleans win.
        definition=deepcopy(definition)
        try:
            template_barring={item['identity']:item['barred'] for item in self.legacy_profile(record)['public_identities']}
        except (ValueError,ET.ParseError,jinja2.TemplateError):template_barring={}
        for item in definition.get('public_identities',[]):
            native_private=set(definition.get('private_identities',[]))-set(definition.get('digest_identity_aliases',{}))
            private_derived=item['identity'] in {'sip:'+private for private in native_private}|{'sips:'+private for private in native_private}
            key=validate_provisioned_public_uri(item['identity'],private_derived=private_derived)
            if 'barred' not in item and key in template_barring:item['barred']=template_barring[key]
        return self.validate_definition(definition,allow_partial_sets=allow_partial_sets)

    def provision(self,profile_id,definition,replace=False,clear_authentication_pending=False,connection=None):
        with (nullcontext(connection) if connection is not None else self.transaction([profile_id])) as c:
            record=self.record(profile_id,c)
            d=self.prepare_definition(record,definition)
            present=c.execute(select(self.profiles).where(self.profiles.c.ims_subscriber_id==profile_id)).first()
            if present and not replace:raise ValueError('Cx profile exists; use explicit replacement')
            if present and not clear_authentication_pending:
                current=self.validate_definition(json.loads(present._mapping['definition']))
                before=deepcopy(current);after=deepcopy(d)
                for field in ('unregistered_service','unregistered_service_policy'):
                    before.pop(field,None);after.pop(field,None)
                if before==after and current!=d:
                    # Routing-policy-only edit: do not rebuild the identity index
                    # or disturb an assigned/registered subscriber's runtime state.
                    c.execute(update(self.profiles).where(self.profiles.c.ims_subscriber_id==profile_id).values(definition=json.dumps(d)))
                    return d
            state=c.execute(select(self.states).where(self.states.c.ims_subscriber_id==profile_id)).mappings().first()
            clear_pending=False
            if state and state['scscf']:
                if not clear_authentication_pending:raise ValueError('De-register before changing the provisioned Cx profile')
                groups=json.loads(state['groups_json'])
                if state['registered_at'] or any(group.get('registered') or group.get('state') in ('registered','unregistered') for group in groups.values()):
                    raise ValueError('Cannot clear authentication pending on a registered or stored unregistered subscription')
                if not any(group.get('pending') for group in groups.values()):
                    raise ValueError('Assignment has no unfinished authentication to clear')
                clear_pending=True
            if not state and record.get('scscf') and record.get('scscf_timestamp'):raise ValueError('De-register the legacy active subscription before changing its Cx profile')
            for kind,identities in [('private',d['private_identities']),('public',[p['identity'] for p in d['public_identities']])]:
                for identity in identities:
                    other=c.execute(select(self.identities.c.ims_subscriber_id).where(self.identities.c.identity==identity,self.identities.c.kind==kind)).first()
                    if other and other[0]!=profile_id:raise ValueError('Identity already provisioned under another subscription')
            if clear_pending:
                # This is an explicit OAM operation in the profile transaction.
                # SQN and native AuC/subscriber data are never reset here.
                c.execute(delete(self.states).where(self.states.c.ims_subscriber_id==profile_id))
                c.execute(update(self.ims).where(self.ims.c.ims_subscriber_id==profile_id).values(
                    scscf=None,scscf_realm=None,scscf_peer=None,scscf_timestamp=None))
            c.execute(delete(self.identities).where(self.identities.c.ims_subscriber_id==profile_id))
            if present:c.execute(update(self.profiles).where(self.profiles.c.ims_subscriber_id==profile_id).values(definition=json.dumps(d)))
            else:c.execute(self.profiles.insert().values(ims_subscriber_id=profile_id,definition=json.dumps(d)))
            for kind,values in [('private',[identity for identity in d['private_identities'] if identity not in d.get('digest_identity_aliases',{})]),('public',[p['identity'] for p in d['public_identities']])]:
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

    def resolve(self,public,private=None,c=None,canonical_private=False):
        if c is None:
            with self.engine.connect() as conn:return self.resolve(public,private,conn,canonical_private)
        record,d=self.find(public,'public',c)
        item=next(x for x in d['public_identities'] if x['identity']==public_key(public))
        if private is not None:
            try:requested=private_key(private)
            except ValueError:raise CxError(5001,reason='invalid_private_identity_format')
            target=d.get('digest_identity_aliases',{}).get(requested,requested)
            if target!=requested:
                # Compatibility names are scoped by a provisioned public
                # profile, never by a global number search or a learned binding.
                other=c.execute(select(self.identities.c.ims_subscriber_id).where(self.identities.c.identity==requested,self.identities.c.kind=='private')).first()
                if other and other[0]!=record['ims_subscriber_id']:raise CxError(5002)
                if requested not in item['private_identities']:raise CxError(5002)
            private_record,_=self.find(target,'private',c)
            if private_record['ims_subscriber_id']!=record['ims_subscriber_id'] or target not in item['private_identities']:raise CxError(5002)
        return {'record':record,'definition':d,'public':item,
                'private':(target if canonical_private else requested) if private is not None else None}

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

    @staticmethod
    def validate_live_ifc(xml_text):
        """Only iFC nodes are editable; public identities and registration state are not."""
        if not isinstance(xml_text,str) or len(xml_text)>131072 or '<!DOCTYPE' in xml_text.upper() or '<!ENTITY' in xml_text.upper():
            raise ValueError('Invalid or oversized iFC XML')
        root=ET.fromstring('<IFCList>'+xml_text+'</IFCList>')
        if any(child.tag!='InitialFilterCriteria' for child in root):
            raise ValueError('Only InitialFilterCriteria elements are allowed')
        for ifc in root:
            if ifc.find('Priority') is None or ifc.find('ApplicationServer/ServerName') is None:
                raise ValueError('Each iFC needs Priority and ApplicationServer/ServerName')
        return ''.join(ET.tostring(child,encoding='unicode') for child in root)

    def live_ifc_get(self,profile_id,set_id):
        with self.engine.connect() as c:
            record=self.record(profile_id,c);d=self.definition(record,c)
            if set_id not in {p['set_id'] for p in d['public_identities']}:raise ValueError('Unknown IRS')
            row=c.execute(select(self.live_ifc).where(self.live_ifc.c.ims_subscriber_id==profile_id,self.live_ifc.c.set_id==set_id)).mappings().first()
            profile={'record':record,'definition':d,'public':next(p for p in d['public_identities'] if p['set_id']==set_id)}
            if row:return {'set_id':set_id,'version':row['version'],'ifc_xml':row['ifc_xml'],'source':'override'}
            root=ET.fromstring(self.user_data(profile))
            fragment=''.join(ET.tostring(x,encoding='unicode') for sp in root.findall('ServiceProfile') for x in sp.findall('InitialFilterCriteria'))
            return {'set_id':set_id,'version':0,'ifc_xml':fragment,'source':'template'}

    def live_ifc_save(self,profile_id,set_id,xml_text,expected_version):
        fragment=self.validate_live_ifc(xml_text)
        with self.transaction([profile_id]) as c:
            record=self.record(profile_id,c);d=self.definition(record,c)
            if not c.execute(select(self.profiles.c.ims_subscriber_id).where(self.profiles.c.ims_subscriber_id==profile_id)).first():
                raise ValueError('Explicit Cx profile required for live edits')
            if set_id not in {p['set_id'] for p in d['public_identities']}:raise ValueError('Unknown IRS')
            row=c.execute(select(self.live_ifc).where(self.live_ifc.c.ims_subscriber_id==profile_id,self.live_ifc.c.set_id==set_id).with_for_update()).mappings().first()
            version=row['version'] if row else 0
            if version!=expected_version:raise ValueError('Version conflict: reload before saving')
            values={'ifc_xml':fragment,'version':version+1,'updated_at':datetime.now(timezone.utc).replace(tzinfo=None)}
            if row:c.execute(update(self.live_ifc).where(self.live_ifc.c.ims_subscriber_id==profile_id,self.live_ifc.c.set_id==set_id).values(**values))
            else:c.execute(self.live_ifc.insert().values(ims_subscriber_id=profile_id,set_id=set_id,**values))
            return {'set_id':set_id,'version':version+1,'saved':True}

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
        # Replace only iFC nodes in the selected IRS; preserve PublicIdentity and barring.
        with self.engine.connect() as c:
            row=c.execute(select(self.live_ifc.c.ifc_xml).where(
                self.live_ifc.c.ims_subscriber_id==profile['record']['ims_subscriber_id'],
                self.live_ifc.c.set_id==set_id)).first()
        if row:
            overrides=ET.fromstring('<IFCList>'+row[0]+'</IFCList>')
            for sp in service_profiles:
                for element in list(sp.findall('InitialFilterCriteria')):sp.remove(element)
            for element in overrides:
                service_profiles[0].append(element)
        for sp in service_profiles:
            if not sp.findall('PublicIdentity'):root.remove(sp)
        return ET.tostring(root,encoding='unicode')
