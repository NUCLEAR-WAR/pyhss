# Copyright 2026 PyHSS contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Native API provisioning: IMS rows and static Cx profiles share one transaction."""
from copy import deepcopy
from datetime import datetime,timezone
import ast,json
from sqlalchemy import select,delete
from sqlalchemy.orm import Session
from cx_repository import CxRepository,private_key,public_key,validate_provisioned_public_uri
from database import IMS_SUBSCRIBER,SUBSCRIBER,AUC

class ProvisioningConflict(ValueError):pass

def e164(value):
    value=''.join(ch for ch in str(value or '').strip() if ch not in ' ().-\t\r\n')
    if value.startswith('00'):value='+'+value[2:]
    digits=value[1:] if value.startswith('+') else value
    if not digits.isascii() or not digits.isdigit() or not 1<=len(digits)<=15 or digits.startswith('0'):
        raise ValueError('MSISDN must be a full international E.164 telephone number')
    return '+'+digits

def numbers(record):
    values=[record.get('msisdn')] if record.get('msisdn') else []
    additional=record.get('msisdn_list') or []
    if isinstance(additional,str):
        try:additional=json.loads(additional)
        except (ValueError,TypeError):
            try:additional=ast.literal_eval(additional)
            except (ValueError,SyntaxError):additional=[part.strip() for part in additional.split(',') if part.strip()]
    if not isinstance(additional,(list,tuple)):raise ValueError('msisdn_list must be a list or comma-separated numbers')
    return list(dict.fromkeys(e164(value) for value in values+list(additional) if value))

def normalize_native(payload):
    result=deepcopy(payload)
    if 'msisdn' in result and result['msisdn'] is not None:result['msisdn']=e164(result['msisdn'])[1:]
    if 'msisdn_list' in result:
        result['msisdn_list']=json.dumps([value[1:] for value in numbers({'msisdn_list':result['msisdn_list']})])
    return result

class CxProvisioning:
    def __init__(self,database,config):
        self.db=database;self.config=config;self.repo=CxRepository(database,config)

    @staticmethod
    def record(obj):return {column.name:getattr(obj,column.name) for column in obj.__table__.columns}

    def realm(self,policy,existing=None):
        value=policy.get('realm') or (existing or {}).get('provisioning',{}).get('realm') or self.config.get('hss',{}).get('cx',{}).get('realm')
        if not value:
            mcc,mnc=self.repo.network_codes();value='ims.mnc'+mnc.zfill(3)+'.mcc'+mcc+'.3gppnetwork.org'
        private_key('realm-check@'+str(value));return str(value).lower()

    def definition(self,record,policy=None,existing=None,previous=None):
        policy=deepcopy(policy or {})
        if not isinstance(policy,dict):raise ValueError('cx must be an object')
        policy.pop('clear_authentication_pending',None)
        for field in ('bar_private_impu','unregistered_service'):
            if field in policy and type(policy[field]) is not bool:raise ValueError('cx.'+field+' must be a boolean')
        if 'unregistered_service_policy' in policy and policy['unregistered_service_policy'] not in ('auto','enabled','disabled'):
            raise ValueError('cx.unregistered_service_policy must be auto, enabled or disabled')
        if 'private_identities' in policy:
            self.repo.xml(record)
            return self.repo.prepare_definition(record,policy)
        meta=(existing or {}).get('provisioning',{})
        mode=policy.get('authentication') or meta.get('authentication')
        if not mode and existing:
            schemes=set()
            for value in existing.get('authentication_schemes',{}).values():schemes.update([value] if isinstance(value,str) else value)
            schemes.add(existing['authentication_scheme'])
            mode='dual' if schemes=={'SIP Digest','Digest-AKAv1-MD5'} else 'sip_digest' if schemes=={'SIP Digest'} else 'aka'
        mode=mode or 'aka'
        if mode not in ('aka','sip_digest','dual'):raise ValueError('cx.authentication must be aka, sip_digest or dual')
        realm=self.realm(policy,existing)
        key=str(record.get('imsi') or '').strip()
        if not key:raise ValueError('IMS subscriber requires a native IMSI / identity key')
        primary=private_key(policy.get('private_identity') or (meta.get('private_identity') if meta.get('custom_private_identity') else None) or key+'@'+realm)
        set_id=policy.get('set_id') or meta.get('set_id') or ('fixed' if mode!='aka' else 'default')
        # Generated from provisioned fields, never derived from an incoming REGISTER.
        private=[primary];public=[];aliases={}
        for number in numbers(record):
            # Match the operator's bare client identity. Digest bootstrap
            # aliases below are metadata, not indexed authentication IMPIs.
            for identity in ('sip:'+number+'@'+realm,'tel:'+number):
                public.append({'identity':identity,'set_id':set_id})
            if mode!='aka':
                for alias in (number+'@'+realm,number[1:]+'@'+realm):
                    if alias!=primary:
                        private.append(alias);aliases[alias]=primary
        private_public='sip:'+primary
        if not any(item['identity']==private_public for item in public):
            public.append({'identity':private_public,'set_id':set_id,'barred':policy.get('bar_private_impu',meta.get('bar_private_impu',True))})
        elif 'bar_private_impu' in policy:
            next(item for item in public if item['identity']==private_public)['barred']=policy['bar_private_impu']
        private=list(dict.fromkeys(private))
        for item in public:item['private_identities']=list(private)
        allowed=['Digest-AKAv1-MD5','SIP Digest'] if mode=='dual' else ['SIP Digest'] if mode=='sip_digest' else ['Digest-AKAv1-MD5']
        if 'unregistered_service_policy' in policy:unregistered_mode=policy['unregistered_service_policy']
        elif 'unregistered_service' in policy:unregistered_mode='enabled' if policy['unregistered_service'] else 'disabled'
        elif existing is not None:unregistered_mode=self.repo.unregistered_service_policy(existing)
        else:unregistered_mode='auto'
        unregistered=self.repo.ifc_has_terminating_unregistered_service(self.repo.xml(record)) if unregistered_mode=='auto' else unregistered_mode=='enabled'
        extra=policy.get('additional_public_identities',meta.get('additional_public_identities',[]))
        if not isinstance(extra,list):raise ValueError('cx.additional_public_identities must be a list of full public URIs or identity objects')
        explicit=[]
        for item in extra:
            item={'identity':item} if isinstance(item,str) else deepcopy(item)
            if not isinstance(item,dict) or 'identity' not in item:raise ValueError('Additional public identity requires a full URI')
            item['identity']=validate_provisioned_public_uri(item['identity'])
            previous_item=next((entry for entry in (existing or {}).get('public_identities',[]) if entry['identity']==item['identity']),{})
            for field in ('set_id','barred','can_register'):
                if field in previous_item:item.setdefault(field,previous_item[field])
            item.setdefault('set_id',set_id)
            if any(entry['identity']==item['identity'] for entry in public+explicit):raise ValueError('Duplicate additional public identity: '+item['identity'])
            item.setdefault('private_identities',list(private));explicit.append(item)
        result={'private_identities':private,'public_identities':public,
            'authentication_scheme':allowed[0],'authentication_schemes':{identity:allowed if identity==primary else 'SIP Digest' for identity in private},
            'digest_realm':policy.get('digest_realm') or realm,
            'visited_networks':policy.get('visited_networks') or (existing or {}).get('visited_networks') or [realm],
            'digest_identity_aliases':aliases,'unregistered_service':unregistered,'unregistered_service_policy':unregistered_mode,
            'service_type':policy.get('service_type') or (existing or {}).get('service_type') or ('fixed_voice' if mode=='sip_digest' else 'mobile_voice_data'),
            'provisioning':{'authentication':mode,'realm':realm,'set_id':set_id,'private_identity':primary,
                'custom_private_identity':bool(policy.get('private_identity') or meta.get('custom_private_identity')),
                'managed_private':list(private),'managed_public':[item['identity'] for item in public],
                'bar_private_impu':next(item.get('barred',False) for item in public if item['identity']==private_public),'additional_public_identities':deepcopy(explicit)}}
        if existing:
            # Preserve explicitly provisioned non-generated identities and their policies.
            old_meta=existing.get('provisioning',{})
            if old_meta:
                old_private=set(old_meta.get('managed_private',[]));old_public=set(old_meta.get('managed_public',[]))
            else:
                old_record=previous or record;old_realm=existing.get('digest_realm') or realm
                old_primary=str(old_record.get('imsi') or '')+'@'+old_realm
                old_private={old_primary};old_public={'sip:'+old_primary}
                for number in numbers(old_record):
                    old_private.update((number+'@'+old_realm,number[1:]+'@'+old_realm))
                    # Without ownership metadata, a manually stored no-plus URI
                    # may be deliberate. Never infer that it was generated.
                    old_public.update(('sip:'+number+'@'+old_realm,'sip:'+number+'@'+old_realm+';user=phone','tel:'+number))
            old_explicit={item['identity'] for item in old_meta.get('additional_public_identities',[])}
            explicit_ids={item['identity'] for item in explicit}
            custom_public=[] if 'additional_public_identities' in policy else [deepcopy(item) for item in existing['public_identities'] if item['identity'] not in old_public|old_explicit|explicit_ids]
            retained=set(identity for item in custom_public+explicit for identity in item['private_identities'])
            custom_private=[identity for identity in existing['private_identities'] if identity not in old_private or identity in retained]
            result['private_identities']=list(dict.fromkeys(private+custom_private))
            result['public_identities']+=custom_public
            for identity in custom_private:
                result['authentication_schemes'].setdefault(identity,existing.get('authentication_schemes',{}).get(identity,existing['authentication_scheme']))
            for source,target in existing.get('digest_identity_aliases',{}).items():
                if source in result['private_identities'] and target in result['private_identities']:result['digest_identity_aliases'].setdefault(source,target)
            # Existing custom members of a generated implicit set remain consistently associated.
            for group in {item['set_id'] for item in result['public_identities']}:
                members=[item for item in result['public_identities'] if item['set_id']==group]
                associations=list(dict.fromkeys(identity for item in members for identity in item['private_identities']))
                for item in members:item['private_identities']=list(associations)
        result['public_identities']+=explicit
        # An added service identity in an existing set shares that set's private
        # associations. A complete cx profile remains available for finer policy.
        for group in {item['set_id'] for item in result['public_identities']}:
            members=[item for item in result['public_identities'] if item['set_id']==group]
            associations=list(dict.fromkeys(identity for item in members for identity in item['private_identities']))
            for item in members:item['private_identities']=list(associations)
        # Refuse a profile whose IFC cannot subsequently be returned in SAA.
        # Preserve operator-provisioned barring for existing identities.
        bars={item['identity']:item['barred'] for item in (existing or {}).get('public_identities',[])}
        for identity in meta.get('managed_public',[]):
            if identity.endswith(';user=phone') and identity in bars:
                bars.setdefault(identity[:-len(';user=phone')],bars[identity])
        for item in result['public_identities']:
            generated_private=item['identity']==private_public
            override_private=generated_private and ('bar_private_impu' in policy or bool(meta))
            if item['identity'] in bars and item['identity'] not in explicit_ids and not override_private:
                item['barred']=bars[item['identity']]
        result['provisioning']['bar_private_impu']=next(item.get('barred',False) for item in result['public_identities'] if item['identity']==private_public)
        self.repo.xml(record)
        return self.repo.prepare_definition(record,result)

    def get(self,ident):
        with self.db.engine.connect() as c:
            record=self.repo.record(int(ident),c)
            result=self.db.Sanitize_Datetime(record)
            row=c.execute(select(self.repo.profiles.c.definition).where(self.repo.profiles.c.ims_subscriber_id==int(ident))).first()
            result['cx']=self.repo.validate_definition(json.loads(row[0])) if row else None
            return result

    def _log(self,session,operation_id):
        session.info['operation_id']=operation_id
        self.db.log_changes_before_commit(session)
        session.flush()

    def _save_ims(self,session,c,payload,ident=None,operation_id=None):
        data=normalize_native(payload);policy=data.pop('cx',None)
        if policy is not None and not isinstance(policy,dict):raise ValueError('cx must be an object')
        if policy is not None and 'clear_authentication_pending' in policy and type(policy['clear_authentication_pending']) is not bool:
            raise ValueError('cx.clear_authentication_pending must be a boolean')
        if ident is None:
            obj=IMS_SUBSCRIBER(**data);previous=None;existing=None
            session.add(obj)
        else:
            obj=session.get(IMS_SUBSCRIBER,int(ident))
            if obj is None:raise LookupError('IMS subscriber not found')
            previous=self.record(obj)
            row=c.execute(select(self.repo.profiles.c.definition).where(self.repo.profiles.c.ims_subscriber_id==int(ident))).first()
            existing=self.repo.validate_definition(json.loads(row[0])) if row else None
            for field,value in data.items():
                if field not in self.repo.ims.c:raise ValueError('Unknown IMS subscriber field: '+field)
                if field=='ims_subscriber_id' and value!=obj.ims_subscriber_id:raise ValueError('Cannot change an IMS subscriber database ID')
                setattr(obj,field,value)
        obj.last_modified=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        self._log(session,operation_id)
        record=self.record(obj)
        identity_changed=previous is None or any(previous.get(key)!=record.get(key) for key in ('imsi','msisdn','msisdn_list','ifc_path'))
        route_fields={'unregistered_service','unregistered_service_policy'}
        if existing and not identity_changed and policy and set(policy)<=route_fields:
            if 'unregistered_service' in policy and type(policy['unregistered_service']) is not bool:
                raise ValueError('cx.unregistered_service must be a boolean')
            desired=deepcopy(existing)
            mode=policy.get('unregistered_service_policy')
            if mode is None:
                if type(policy['unregistered_service']) is not bool:raise ValueError('cx.unregistered_service must be a boolean')
                mode='enabled' if policy['unregistered_service'] else 'disabled'
            if mode not in ('auto','enabled','disabled'):raise ValueError('Invalid unregistered service policy')
            desired['unregistered_service_policy']=mode
            desired['unregistered_service']=self.repo.ifc_has_terminating_unregistered_service(self.repo.xml(record)) if mode=='auto' else mode=='enabled'
        else:desired=existing if existing and policy is None and not identity_changed else self.definition(record,policy,existing,previous)
        if existing!=desired or (policy or {}).get('clear_authentication_pending'):
            try:self.repo.provision(obj.ims_subscriber_id,desired,replace=bool(existing),
                    clear_authentication_pending=bool((policy or {}).get('clear_authentication_pending')),connection=c)
            except ValueError as error:
                if 'De-register' in str(error) or 'registered or stored' in str(error):raise ProvisioningConflict(str(error)) from error
                raise
        return self.db.Sanitize_Datetime(record)|{'cx':desired}

    def save(self,payload,ident=None,operation_id=None):
        with self.repo.transaction([int(ident)] if ident is not None else []) as c:
            with Session(bind=c,join_transaction_mode='create_savepoint') as session:
                result=self._save_ims(session,c,payload,ident,operation_id);session.commit()
        self.db.handleWebhook(result,'PATCH' if ident is not None else 'PUT')
        return result

    def _delete_ims(self,session,c,ident,operation_id):
        record=self.repo.record(ident,c)
        state=c.execute(select(self.repo.states).where(self.repo.states.c.ims_subscriber_id==ident)).mappings().first()
        if record.get('scscf_timestamp') or (state and (state['registered_at'] or any(group.get('registered') or group.get('state')=='unregistered' for group in json.loads(state['groups_json']).values()))):
            raise ProvisioningConflict('De-register IMS service before deleting its provisioned identities')
        for table in (self.repo.identities,self.repo.states,self.repo.profiles):c.execute(delete(table).where(table.c.ims_subscriber_id==ident))
        obj=session.get(IMS_SUBSCRIBER,ident);session.delete(obj);self._log(session,operation_id)
        return record

    def remove(self,ident,operation_id=None):
        with self.repo.transaction([int(ident)]) as c:
            with Session(bind=c,join_transaction_mode='create_savepoint') as session:
                record=self._delete_ims(session,c,int(ident),operation_id);session.commit()
        self.db.handleWebhook(self.db.Sanitize_Datetime(record),'DELETE')
        return {'Result':'OK'}

    def create_service(self,payload,operation_id=None):
        if not isinstance(payload,dict):raise ValueError('Subscriber service must be an object')
        auc_data=deepcopy(payload.get('auc') or {});sub_data=normalize_native(payload.get('subscriber') or {})
        ims_data=deepcopy(payload.get('ims_subscriber'))
        if not auc_data or not sub_data:raise ValueError('auc and subscriber objects are required')
        if not sub_data.get('imsi'):raise ValueError('Native subscriber identity key is required')
        if auc_data.get('imsi')!=sub_data.get('imsi'):raise ValueError('AuC and subscriber identity keys must match')
        if ims_data is not None and ims_data.get('imsi')!=sub_data.get('imsi'):raise ValueError('IMS and subscriber identity keys must match')
        with self.repo.transaction() as c:
            with Session(bind=c,join_transaction_mode='create_savepoint') as session:
                for values in (auc_data,sub_data):values['last_modified']=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                auc=AUC(**auc_data);session.add(auc);self._log(session,operation_id)
                sub_data['auc_id']=auc.auc_id;sub=SUBSCRIBER(**sub_data);session.add(sub);self._log(session,operation_id)
                ims=self._save_ims(session,c,ims_data,operation_id=operation_id) if ims_data is not None else None
                result={'auc':{'auc_id':auc.auc_id},'subscriber':self.db.Sanitize_Datetime(self.record(sub)),'ims_subscriber':ims}
                session.commit()
        self.db.handleWebhook(result,'PUT')
        return result

    def options(self):
        return {'realm':self.realm({}),'default_ifc':'default_ifc.xml',
                'authentication_methods':['aka','sip_digest','dual']}

    def update_service(self,ident,payload,operation_id=None):
        if not isinstance(payload,dict):raise ValueError('Subscriber service must be an object')
        ident=int(ident)
        with self.db.engine.connect() as c:
            sub=c.execute(select(SUBSCRIBER.__table__).where(SUBSCRIBER.subscriber_id==ident)).mappings().first()
            if not sub:raise LookupError('Subscriber not found')
            ims_ids=list(c.execute(select(self.repo.ims.c.ims_subscriber_id).where(self.repo.ims.c.imsi==sub['imsi'])).scalars())
        with self.repo.transaction(ims_ids) as c:
            with Session(bind=c,join_transaction_mode='create_savepoint') as session:
                sub=session.get(SUBSCRIBER,ident)
                data=normalize_native(payload.get('subscriber') or {})
                if 'imsi' in data and data['imsi']!=sub.imsi:raise ValueError('Changing the service identity key requires reprovisioning')
                if 'auc_id' in data and data['auc_id']!=sub.auc_id:raise ValueError('Changing the service AuC link requires reprovisioning')
                if 'subscriber_id' in data and data['subscriber_id']!=ident:raise ValueError('Cannot change subscriber database ID')
                ims_payload=deepcopy(payload.get('ims_subscriber'))
                ims=None
                if ims_payload is not None:
                    if 'imsi' in ims_payload and ims_payload['imsi']!=sub.imsi:raise ValueError('IMS and subscriber identity keys must match')
                    ims_id=ims_payload.pop('ims_subscriber_id',ims_ids[0] if ims_ids else None)
                    if ims_id is not None and int(ims_id) not in ims_ids:raise ValueError('IMS row does not belong to this subscriber')
                    if ims_id is None:ims_payload.setdefault('imsi',sub.imsi)
                    ims=self._save_ims(session,c,ims_payload,ims_id,operation_id)
                for field,value in data.items():
                    if field not in SUBSCRIBER.__table__.c:raise ValueError('Unknown subscriber field: '+field)
                    setattr(sub,field,value)
                sub.last_modified=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                auc=session.get(AUC,sub.auc_id)
                for field,value in (payload.get('auc') or {}).items():
                    if field not in ('ki','opc','amf'):raise ValueError('Only authentication credentials may be edited through the service endpoint')
                    if getattr(auc,field)!=value:
                        for ims_id in ims_ids:
                            record=self.repo.record(ims_id,c)
                            state=c.execute(select(self.repo.states.c.registered_at).where(self.repo.states.c.ims_subscriber_id==ims_id)).first()
                            if record.get('scscf_timestamp') or (state and state[0]):raise ProvisioningConflict('De-register IMS before changing authentication credentials')
                        setattr(auc,field,value)
                self._log(session,operation_id)
                result={'subscriber':self.db.Sanitize_Datetime(self.record(sub)),'ims_subscriber':ims,'auc':{'auc_id':sub.auc_id}}
                session.commit()
        self.db.handleWebhook(result,'PATCH');return result

    def snapshot(self):
        result={'_columns':{}}
        with self.db.engine.connect() as c:
            for model in (AUC,SUBSCRIBER,IMS_SUBSCRIBER):
                values=[self.db.Sanitize_Keys(self.db.Sanitize_Datetime(dict(row))) for row in c.execute(select(model.__table__)).mappings()]
                result[model.__tablename__]=values
                result['_columns'][model.__tablename__]=list(model.__table__.c.keys())
            from database import APN
            result['apn']=[self.db.Sanitize_Datetime(dict(row)) for row in c.execute(select(APN.__table__)).mappings()]
            result['_columns']['apn']=list(APN.__table__.c.keys())
            profiles={row[0]:json.loads(row[1]) for row in c.execute(select(self.repo.profiles))}
            result['ims_cx_profile']=[{'ims_subscriber_id':ident,'definition':json.dumps(definition)} for ident,definition in profiles.items()]
            result['_columns']['ims_cx_profile']=['ims_subscriber_id','definition']
            result['_columns']['ims_subscriber'].append('cx')
            for item in result['ims_subscriber']:item['cx']=profiles.get(item['ims_subscriber_id'])
        return result
