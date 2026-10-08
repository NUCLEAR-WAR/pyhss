# Copyright 2026 PyHSS contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio,secrets,uuid
from types import SimpleNamespace
import pytest
import dns.rrset,dns.resolver
import service_discovery as sd
from database import database_connection_settings

DOMAIN=uuid.uuid4().hex+'.invalid'
PORT=secrets.randbelow(60000)+1024
SRV='_api._tcp.'+DOMAIN

class Answer:
    def __init__(self,kind,rows,ttl=10):self.rrset=dns.rrset.from_text(DOMAIN,ttl,'IN',kind,*rows)
    def __iter__(self):return iter(self.rrset)

@pytest.fixture
def resolver():
    records={(SRV,'SRV'):Answer('SRV',['0 0 '+str(PORT)+' target.'+DOMAIN+'.'])};calls=[];clock=[0]
    def query(name,kind,**kwargs):
        calls.append((name,kind))
        answer=records.get((name.rstrip('.'),kind))
        if answer is None:raise dns.resolver.NoAnswer()
        return answer
    return sd.ServiceDiscovery(query,clock=lambda:clock[0]),records,calls,clock

def test_naptr_selects_matching_service_by_order_then_preference(resolver):
    r,rows,calls,_=resolver
    rows[(DOMAIN,'NAPTR')]=Answer('NAPTR',[
        '5 0 "s" "OTHER" "" _other._tcp.'+DOMAIN+'.',
        '20 0 "s" "X-API" "" _late._tcp.'+DOMAIN+'.',
        '10 5 "s" "X-API" "" '+SRV+'.'])
    endpoint=r.resolve({'domain':DOMAIN,'naptr_services':['X-API']})
    assert (endpoint.host,endpoint.port)==('target.'+DOMAIN,PORT)
    assert calls==[(DOMAIN,'NAPTR'),(SRV+'.','SRV')]

def test_dns_changes_are_used_after_ttl_expiry(resolver):
    r,rows,calls,clock=resolver;policy={'domain':DOMAIN,'srv':SRV}
    assert r.resolve(policy).port==PORT
    rows[(SRV,'SRV')]=Answer('SRV',['0 0 '+str(PORT+1)+' next.'+DOMAIN+'.'])
    assert r.resolve(policy).port==PORT and len(calls)==1
    clock[0]=11
    endpoint=r.resolve(policy)
    assert endpoint.host=='next.'+DOMAIN and endpoint.port==PORT+1

def test_srv_priority_is_respected_and_weighted_choice_is_injectable(resolver):
    r,rows,_,_=resolver
    rows[(SRV,'SRV')]=Answer('SRV',['1 5 '+str(PORT)+' a.'+DOMAIN+'.','1 10 '+str(PORT+1)+' b.'+DOMAIN+'.','2 100 '+str(PORT+2)+' backup.'+DOMAIN+'.'])
    r.rng=SimpleNamespace(shuffle=lambda items:None,randint=lambda low,high:high)
    assert r.resolve({'domain':DOMAIN,'srv':SRV}).host=='b.'+DOMAIN

@pytest.mark.parametrize('rows',[None,['0 0 '+str(PORT)+' .']])
def test_missing_or_disabled_service_has_no_fixed_port_fallback(resolver,rows):
    r,records,_,_=resolver
    if rows is None:records.clear()
    else:records[(SRV,'SRV')]=Answer('SRV',rows)
    with pytest.raises(sd.DiscoveryError):r.resolve({'domain':DOMAIN,'srv':SRV})

def test_dns_timeout_does_not_become_srv_default():
    def query(*args,**kwargs):raise dns.resolver.LifetimeTimeout()
    with pytest.raises(sd.DiscoveryError,match='DNS lookup failed'):
        sd.ServiceDiscovery(query).resolve({'domain':DOMAIN,'srv':SRV})

@pytest.mark.parametrize('value',['192.0.2.1','host:1234','http://host',''])
def test_discovery_requires_dns_domain_not_literal_endpoint(value):
    with pytest.raises(sd.DiscoveryError):sd.hostname(value)

def test_native_mysql_driver_settings_use_discovered_port_and_keep_credentials_tls(resolver,monkeypatch):
    r,_,_,_=resolver;monkeypatch.setattr(sd,'discovery',r)
    secret=secrets.token_urlsafe(12)+'@%'
    uri,args=database_connection_settings({'db_type':'mysql','database':'test','username':'operator','password':secret,'ssl_disabled':True,'discovery':{'domain':DOMAIN,'srv':SRV},'server':'ignored.invalid','port':1})
    assert uri.host=='target.'+DOMAIN and uri.port==PORT and uri.password==secret
    assert args=={'ssl_disabled':True}

def test_sql_new_connection_hook_refreshes_endpoint_without_changing_tls(resolver,monkeypatch):
    from sqlalchemy import create_engine
    r,_,_,_=resolver;monkeypatch.setattr(sd,'discovery',r)
    engine=create_engine('mysql+pymysql://operator@unused.invalid/test')
    sd.install_database_discovery(engine,{'domain':DOMAIN,'srv':SRV})
    args={'host':'old.invalid','port':1,'ssl_disabled':True}
    for callback in engine.dialect.dispatch.do_connect:callback(engine.dialect,None,[],args)
    assert args=={'host':'target.'+DOMAIN,'port':PORT,'ssl_disabled':True}
    engine.dispose()

@pytest.mark.parametrize('asynchronous',[False,True])
def test_redis_socket_connect_uses_discovered_endpoint(resolver,monkeypatch,asynchronous):
    r,_,_,_=resolver;monkeypatch.setattr(sd,'discovery',r);seen=[]
    if asynchronous:
        from redis.asyncio.connection import Connection
        async def connect(self):seen.append((self.host,self.port))
        async def to_thread(func,*args):return func(*args)
        monkeypatch.setattr(asyncio,'to_thread',to_thread)
    else:
        from redis.connection import Connection
        def connect(self):seen.append((self.host,self.port))
    monkeypatch.setattr(Connection,'_connect',connect)
    conn=sd.redis_connection_class(asynchronous)(discovery_policy={'domain':DOMAIN,'srv':SRV},host=DOMAIN,port=0)
    if asynchronous:
        coro=conn._connect()
        with pytest.raises(StopIteration):coro.send(None)
    else:conn._connect()
    assert seen==[('target.'+DOMAIN,PORT)]

def test_http_path_and_query_are_preserved_and_tls_cannot_be_downgraded(resolver,monkeypatch):
    r,_,_,_=resolver;monkeypatch.setattr(sd,'discovery',r)
    origin='https://'+DOMAIN;policy={origin:{'domain':DOMAIN,'srv':SRV}}
    assert sd.resolve_http_url(origin+'/api/item?q=1',policy)=='https://target.'+DOMAIN+':'+str(PORT)+'/api/item?q=1'
    policy[origin]['scheme']='http'
    with pytest.raises(sd.DiscoveryError,match='TLS policy'):sd.resolve_http_url(origin+'/api/item',policy)
