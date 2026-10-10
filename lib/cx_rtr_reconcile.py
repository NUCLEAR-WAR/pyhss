"""Conservative post-RTA Cx state reconciliation.

A successful Diameter answer is not proof of SIP contact removal. State changes
are restricted to the exact selected IRS/IMPI and require an unchanged snapshot.
"""
from copy import deepcopy


def reconcile_rtr(repo, subscriber_id, registration_set, private_identity,
                  reason_code, expected_state):
    """Return a structured outcome; never delete subscriber or alter policies.

    The caller MUST invoke this only after a correlated successful RTA.
    A concurrent REGISTER/SAR, changed assignment or changed IRS aborts cleanup.
    """
    if reason_code not in (0, 1, 2, 3):
        raise ValueError('Invalid RTR reason')
    if reason_code == 1:
        return {'hss_state_reconciled': False, 'reconciliation_status': 'external_reassignment_required',
                'message': 'Old S-CSCF RTA does not prove the new assignment; HSS state unchanged'}
    with repo.transaction([subscriber_id]) as connection:
        record = repo.record(subscriber_id, connection)
        definition = repo.definition(record, connection)
        current = repo.state({'record': record, 'definition': definition}, connection)
        expected_group = (expected_state.get('groups') or {}).get(registration_set)
        actual_group = (current.get('groups') or {}).get(registration_set)
        if (not expected_group or actual_group != expected_group or
                any(current.get(k) != expected_state.get(k) for k in ('scscf', 'peer', 'realm'))):
            return {'hss_state_reconciled': False, 'reconciliation_status': 'state_changed',
                    'message': 'Concurrent registration or assignment change; no state overwritten'}
        if reason_code == 3:
            if actual_group.get('registered'):
                return {'hss_state_reconciled': False, 'reconciliation_status': 'active_registration',
                        'message': 'Cannot remove S-CSCF while selected IRS is registered'}
            group = deepcopy(actual_group)
            group['state'] = 'not_registered'
            group['pending'] = []
        else:
            registered = list(actual_group.get('registered') or [])
            if private_identity not in registered:
                return {'hss_state_reconciled': False, 'reconciliation_status': 'identity_not_registered'}
            group = deepcopy(actual_group)
            group['registered'] = [identity for identity in registered if identity != private_identity]
            group['pending'] = [identity for identity in group.get('pending', []) if identity != private_identity]
            group['state'] = 'registered' if group['registered'] else 'not_registered'
        current['groups'][registration_set] = group
        # A single shared S-CSCF assignment is stored for the entire subscriber.
        # Clear it only when NO IRS has a registered IMPI or retained assignment.
        other_active = any(g.get('registered') or g.get('state') == 'unregistered'
                           for g in current['groups'].values())
        if not other_active:
            current['scscf'] = None
            current['realm'] = None
            current['peer'] = None
        repo.save(current, connection)
        return {'hss_state_reconciled': True, 'reconciliation_status': 'updated',
                'affected_registration_set': registration_set,
                'affected_private_identity': private_identity,
                'scscf_assignment_cleared': not other_active,
                'subscriber_deleted': False,
                'sip_contact_removal_verified': False}
