"""Correlated Cx request/answer transport, without registration-state side effects.

This polls the existing inbound diagnostic list. It MUST NOT be used as proof
of subscriber deregistration until the peer's Result-Code is evaluated.
"""
import json
import time
from cx_outbound_correlation import matches_answer, header
from cx_outbound_peer import resolve_peer


def await_correlated_answer(diameter, operation, hostname, timeout=5.0, poll_interval=0.05, peer_hint=None, **kwargs):
    """Queue an RTR/PPR and await its matching RTA/PPA; return structured status.

    The inbound list is read-only; concurrent callers cannot steal each other's
    answers. A matching answer is not necessarily a successful answer.
    """
    operation = operation.upper()
    if operation not in ('RTR', 'PPR'):
        raise ValueError('Only RTR and PPR are supported')
    if timeout <= 0 or timeout > 60:
        raise ValueError('Timeout must be within (0, 60] seconds')
    def debug(message, level='debug'):
        try:
            diameter.logTool.log(service='HSS', level=level,
                                 message='[CxOutbound] [%s] %s' % (operation, message),
                                 redisClient=diameter.redisMessaging)
        except Exception:
            pass  # Diagnostics must never interrupt a Diameter operation.

    debug('Resolving assigned S-CSCF=%r peer_hint=%r' % (hostname, peer_hint))
    resolved = resolve_peer(diameter, hostname, peer_hint=peer_hint, debug=debug)
    if resolved['status'] != 'resolved':
        debug('Peer resolution failed: %s' % resolved['status'], 'warning')
        return {'status': resolved['status'], 'operation': operation,
                'peer_resolution': resolved.get('diagnostics')}
    peer = resolved['peer']
    hostname = resolved['hostname']
    debug('Selected Diameter Origin-Host=%s endpoint=%s:%s' %
          (hostname, peer.IpAddress, peer.Port))
    request = diameter.sendDiameterRequest(requestType=operation, hostname=hostname, **kwargs)
    if not request:
        debug('sendDiameterRequest returned no packet', 'error')
        return {'status': 'queue_failed', 'operation': operation}
    header(request)  # fail closed if the generated request is malformed
    # Answers are dispatched by hssService into a per-transaction mailbox.
    # Never read the shared inbound request queue (it is consumed by HSS).
    req_header = header(request)
    mailbox = 'cx-answer-%d-%s-%s' % (
        req_header['command'], req_header['hop_by_hop'].hex(),
        req_header['end_to_end'].hex())
    debug('RTR/PPR queued; mailbox=%s timeout=%.1fs' % (mailbox, timeout))
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        messages = diameter.redisMessaging.getList(
            key=mailbox, usePrefix=True, prefixHostname=diameter.hostname,
            prefixServiceName='diameter') or []
        for item in messages:
            try:
                if isinstance(item, bytes):
                    item = item.decode('utf-8')
                entry = json.loads(item) if isinstance(item, str) else item
                if (entry.get('SenderIp') != peer.IpAddress
                        or str(entry.get('SenderPort')) != str(peer.Port)):
                    continue
                answer = entry.get('InboundHex')
                if answer and matches_answer(request, answer, operation):
                    from cx_outbound_results import evaluate_answer
                    result = evaluate_answer(request, answer, operation)
                    debug('Correlated answer received: status=%s elapsed=%.3fs' % (result['status'], time.monotonic()-started))
                    return {'status': result['status'], 'operation': operation,
                            'result': result, 'request': request, 'answer': answer,
                            'elapsed_seconds': round(time.monotonic()-started, 3)}
            except (ValueError, TypeError, KeyError, AttributeError):
                continue
        time.sleep(poll_interval)
    debug('Timed out waiting for correlated answer after %.1fs' % timeout, 'warning')
    return {'status': 'timeout', 'operation': operation,
            'request': request, 'elapsed_seconds': round(time.monotonic()-started, 3)}
