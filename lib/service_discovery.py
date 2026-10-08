# Copyright 2026 PyHSS contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Configured service discovery. DNS mode never falls back to fixed ports/IPs."""
from dataclasses import dataclass
import ipaddress,random,re,threading,time
from urllib.parse import urlsplit,urlunsplit

class DiscoveryError(ValueError):pass

def hostname(value):
    value=str(value).rstrip('.').lower()
    try:ipaddress.ip_address(value)
    except ValueError:pass
    else:raise DiscoveryError('Service discovery requires a DNS name, not an IP address')
    if not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',value):
        raise DiscoveryError('Invalid DNS service domain')
    return value

@dataclass(frozen=True)
class ServiceEndpoint:
    host:str
    port:int
    transport:str
    scheme:str
    def http_url(self,path=''):
        if self.scheme not in ('http','https'):raise DiscoveryError('HTTP service requires http or https scheme')
        return self.scheme+'://'+self.host+':'+str(self.port)+path

class ServiceDiscovery:
    def __init__(self,query=None,clock=time.monotonic,rng=None):
        self.query=query;self.clock=clock;self.rng=rng or random.SystemRandom();self.cache={};self.lock=threading.RLock()

    def records(self,name,kind,timeout):
        key=(name.lower(),kind)
        with self.lock:
            cached=self.cache.get(key)
            if cached and cached[0]>self.clock():return cached[1]
        import dns.resolver
        try:
            answer=(self.query or dns.resolver.resolve)(name,kind,search=False,lifetime=timeout)
        except (dns.resolver.NXDOMAIN,dns.resolver.NoAnswer):return []
        except Exception as error:raise DiscoveryError('DNS lookup failed for '+kind+' '+name) from error
        records=list(answer);ttl=float(answer.rrset.ttl)
        if hasattr(answer,'expiration'):ttl=min(ttl,max(0,answer.expiration-time.time()))
        with self.lock:self.cache[key]=(self.clock()+max(0,ttl),records)
        return records

    def resolve(self,policy):
        if not isinstance(policy,dict) or not policy.get('domain'):raise DiscoveryError('Discovery policy requires domain')
        domain=hostname(policy['domain']);transport=policy.get('transport','tcp').lower()
        if transport not in ('tcp','udp','sctp'):raise DiscoveryError('Unsupported discovery transport')
        timeout=float(policy.get('timeout',4))
        if not 0<timeout<=60:raise DiscoveryError('DNS timeout must be between 0 and 60 seconds')
        services=policy.get('naptr_services',[])
        if not isinstance(services,list) or any(not isinstance(value,str) for value in services):raise DiscoveryError('naptr_services must be a list of tags')
        srv=policy.get('srv')
        if services:
            tags={value.lower() for value in services}
            naptr=[r for r in self.records(domain,'NAPTR',timeout) if r.flags.lower()==b's' and not r.regexp and r.service.decode('ascii').lower() in tags]
            if naptr:
                first=min(naptr,key=lambda r:(r.order,r.preference))
                srv=str(first.replacement)
        if not srv:raise DiscoveryError('No matching NAPTR record; configure the direct SRV query name')
        if not re.fullmatch(r'_[A-Za-z0-9-]+\._(?:tcp|udp|sctp)\.[A-Za-z0-9.-]+\.?',str(srv)):
            raise DiscoveryError('Invalid SRV service name')
        if str(srv).split('.')[1].lower()!='_'+transport:raise DiscoveryError('SRV transport does not match client policy')
        records=self.records(str(srv),'SRV',timeout)
        if not records:raise DiscoveryError('No SRV endpoints for '+str(srv))
        priority=min(r.priority for r in records);candidates=[r for r in records if r.priority==priority]
        if any(str(r.target)=='.' for r in candidates):raise DiscoveryError('DNS explicitly marks service unavailable')
        # RFC 2782: zero-weight records precede others, with a draw including 0.
        candidates=list(candidates);self.rng.shuffle(candidates);candidates.sort(key=lambda r:r.weight!=0)
        total=sum(r.weight for r in candidates)
        if not total:chosen=self.rng.choice(candidates)
        else:
            draw=self.rng.randint(0,total);cumulative=0;chosen=candidates[-1]
            for record in candidates:
                cumulative+=record.weight
                if cumulative>=draw:chosen=record;break
        if not 1<=chosen.port<=65535:raise DiscoveryError('Invalid port in SRV record')
        return ServiceEndpoint(hostname(str(chosen.target)),int(chosen.port),transport,policy.get('scheme','http'))

discovery=ServiceDiscovery()

def resolve_http_url(url,policies=None):
    """Resolve only explicitly configured HTTP origins; preserve resource paths."""
    parsed=urlsplit(url)
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.fragment:
        raise DiscoveryError('HTTP endpoint must be an absolute URL without credentials or fragment')
    origin=urlunsplit((parsed.scheme,parsed.netloc,'','',''))
    policy=(policies or {}).get(origin)
    if policy is None:return url
    if policy.get('scheme',parsed.scheme)!=parsed.scheme:raise DiscoveryError('Discovery cannot change HTTP TLS policy')
    endpoint=discovery.resolve(dict(policy,scheme=parsed.scheme))
    if endpoint.transport!='tcp':raise DiscoveryError('HTTP clients require TCP discovery')
    return endpoint.http_url(parsed.path or '/')+('?' + parsed.query if parsed.query else '')

def install_database_discovery(engine,policy):
    """Refresh discovery for each new pooled SQL connection, retaining TLS/auth."""
    if policy is None:return
    from sqlalchemy import event
    def connect(dialect,connection_record,args,parameters):
        endpoint=discovery.resolve(policy)
        if endpoint.transport!='tcp':raise DiscoveryError('SQL database requires TCP discovery')
        parameters.update(host=endpoint.host,port=endpoint.port)
    event.listen(engine,'do_connect',connect)

def redis_connection_class(asynchronous=False):
    """Resolve when Redis opens/reopens a socket, not on every Redis command."""
    if asynchronous:
        import asyncio
        from redis.asyncio.connection import Connection
        class DNSConnection(Connection):
            def __init__(self,*args,discovery_policy,**kwargs):
                self.discovery_policy=discovery_policy;super().__init__(*args,**kwargs)
            async def _connect(self):
                endpoint=await asyncio.to_thread(discovery.resolve,self.discovery_policy)
                if endpoint.transport!='tcp':raise DiscoveryError('Redis requires TCP discovery')
                self.host,self.port=endpoint.host,endpoint.port
                await super()._connect()
    else:
        from redis.connection import Connection
        class DNSConnection(Connection):
            def __init__(self,*args,discovery_policy,**kwargs):
                self.discovery_policy=discovery_policy;super().__init__(*args,**kwargs)
            def _connect(self):
                endpoint=discovery.resolve(self.discovery_policy)
                if endpoint.transport!='tcp':raise DiscoveryError('Redis requires TCP discovery')
                self.host,self.port=endpoint.host,endpoint.port
                return super()._connect()
    return DNSConnection
