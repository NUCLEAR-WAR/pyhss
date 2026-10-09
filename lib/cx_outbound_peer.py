"""Resolve the assigned S-CSCF to an existing connected Diameter peer.

No configured paths, addresses or domains are embedded in this module.
"""
from urllib.parse import urlsplit


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


def resolve_peer(diameter, assigned_scscf, peer_hint=None, debug=None):
    """Fail closed unless the assigned S-CSCF has one connected exact match.

    The stored semicolon-delimited peer metadata is diagnostic only: it must
    never override the S-CSCF assignment or select an unrelated peer.
    """
    log = debug or (lambda message, level='debug': None)
    target = _host(assigned_scscf)
    if not target:
        return {'status': 'invalid_destination', 'diagnostics': 'No assigned S-CSCF host'}
    try:
        peer = diameter.getPeerByHostname(hostname=target)
    except Exception as exc:
        log('getPeerByHostname failed for %s: %s' % (target, type(exc).__name__), 'error')
        return {'status': 'peer_lookup_failed', 'diagnostics': type(exc).__name__}
    if not peer or not getattr(peer, 'Connected', False) or not getattr(peer, 'IpAddress', None) or not getattr(peer, 'Port', None):
        log('No connected Diameter peer for %s (stored hint=%r)' % (target, peer_hint), 'warning')
        return {'status': 'peer_unavailable', 'diagnostics': 'No connected peer for assigned S-CSCF %s' % target}
    actual = _host(getattr(peer, 'Hostname', ''))
    if actual != target:
        # Reject DRA fallback and other substitutions for subscriber-changing operations.
        log('Rejected peer substitution: assigned=%s resolved=%s' % (target, actual), 'warning')
        return {'status': 'peer_mismatch', 'diagnostics': 'Connected peer does not match assigned S-CSCF'}
    return {'status': 'resolved', 'peer': peer, 'hostname': actual}
