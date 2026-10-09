"""Resolve the assigned S-CSCF to an existing connected Diameter peer.

No configured paths, addresses or domains are embedded in this module.
"""
from urllib.parse import urlsplit
import json


def _host(value):
    if not isinstance(value, str):
        return ''
    value = value.strip()
    if not value:
        return ''
    if value.lower().startswith(('sip:', 'sips:')):
        parsed = urlsplit(value.replace(':', '://', 1))
        return (parsed.hostname or '').lower().rstrip('.')
    return value.lower().rstrip('.')


def _peer_info(item):
    """Expose only connection metadata, never credentials or packet bodies."""
    if isinstance(item, (str, bytes)):
        try:
            item = json.loads(item)
        except (TypeError, ValueError):
            return {"parse_error": "invalid_json"}
    if hasattr(item, 'model_dump'):
        item = item.model_dump()
    if not isinstance(item, dict):
        return {"parse_error": type(item).__name__}
    return {
        "hostname": str(item.get('Hostname') or ''),
        "connected": item.get('Connected'),
        "ip": str(item.get('IpAddress') or ''),
        "port": str(item.get('Port') or ''),
    }


def resolve_peer(diameter, assigned_scscf, peer_hint=None, debug=None):
    """Resolve only the assigned S-CSCF; never fall back to an unrelated peer."""
    log = debug or (lambda message, level='debug': None)
    target = _host(assigned_scscf)
    diagnostics = {
        'assigned_scscf': str(assigned_scscf or ''),
        'requested_hostname': target,
        'stored_peer_hint': str(peer_hint or ''),
        'peer_registry_name': str(getattr(diameter, 'diameterPeerKey', '')),
        'peer_registry_prefix_hostname': str(getattr(diameter, 'hostname', '')),
        'peer_registry_prefix_service': 'diameter',
        'peer_lookup_result': 'not_attempted',
    }
    if not target:
        diagnostics['peer_lookup_result'] = 'invalid_destination'
        return {'status': 'invalid_destination', 'diagnostics': diagnostics}
    try:
        registry = diameter.redisMessaging.getAllHashData(
            name=diameter.diameterPeerKey, usePrefix=True,
            prefixHostname=diameter.hostname, prefixServiceName='diameter') or {}
        diagnostics['connected_peer_count'] = 0
        diagnostics['peer_registry_entry_count'] = len(registry)
        candidates = [_peer_info(v) for v in registry.values()]
        diagnostics['candidate_peers'] = candidates
        diagnostics['connected_peer_count'] = sum(p.get('connected') is True for p in candidates)
        log('peer registry name=%r prefix_hostname=%r entries=%d candidates=%s' % (
            diagnostics['peer_registry_name'], diagnostics['peer_registry_prefix_hostname'],
            len(registry), candidates))
    except Exception as exc:
        diagnostics['peer_lookup_result'] = 'registry_error'
        diagnostics['registry_error_type'] = type(exc).__name__
        log('peer registry read failed: %s' % type(exc).__name__, 'error')
        return {'status': 'peer_lookup_failed', 'diagnostics': diagnostics}
    exact = [p for p in candidates if _host(p.get('hostname')) == target]
    connected = [p for p in exact if p.get('connected') is True and p.get('ip') and p.get('port')]
    if len(connected) > 1:
        diagnostics['peer_lookup_result'] = 'peer_ambiguous'
        log('multiple connected peers match assigned host %s' % target, 'warning')
        return {'status': 'peer_ambiguous', 'diagnostics': diagnostics}
    if not connected:
        diagnostics['peer_lookup_result'] = (
            'peer_registry_empty' if not candidates else
            'peer_disconnected' if exact else 'hostname_not_found')
        log('peer resolution failed: %s target=%s' % (diagnostics['peer_lookup_result'], target), 'warning')
        return {'status': 'peer_unavailable', 'diagnostics': diagnostics}
    try:
        peer = diameter.getPeerByHostname(hostname=target)
    except Exception as exc:
        diagnostics['peer_lookup_result'] = 'get_peer_exception'
        diagnostics['exception_type'] = type(exc).__name__
        log('getPeerByHostname failed: %s' % type(exc).__name__, 'error')
        return {'status': 'peer_lookup_failed', 'diagnostics': diagnostics}
    if not peer or _host(getattr(peer, 'Hostname', '')) != target:
        diagnostics['peer_lookup_result'] = 'get_peer_mismatch'
        log('registry matched but getPeerByHostname returned no exact S-CSCF', 'warning')
        return {'status': 'peer_unavailable', 'diagnostics': diagnostics}
    if not getattr(peer, 'Connected', False) or not getattr(peer, 'IpAddress', None) or not getattr(peer, 'Port', None):
        diagnostics['peer_lookup_result'] = 'peer_disconnected'
        return {'status': 'peer_unavailable', 'diagnostics': diagnostics}
    diagnostics['peer_lookup_result'] = 'resolved'
    diagnostics['selected_peer'] = _peer_info(peer)
    return {'status': 'resolved', 'peer': peer, 'hostname': target, 'diagnostics': diagnostics}
