"""Post-RTA HSS cleanup for a selected Cx registration scope.

Only a correlated successful RTA can invoke this operation. All writes occur
under the subscriber lock and only if the selected IRS snapshot is unchanged.
"""
from copy import deepcopy


def reconcile_rtr(repo, subscriber_id, registration_set, private_identity,
                  reason_code, expected_state):
    if reason_code not in (0, 1, 2, 3):
        raise ValueError('Invalid RTR reason')
    if reason_code == 1:
        return {'hss_state_reconciled': False,
                'reconciliation_status': 'external_reassignment_required',
                'message': 'New S-CSCF assignment must be confirmed separately'}
    with repo.transaction([subscriber_id]) as connection:
        record = repo.record(subscriber_id, connection)
        definition = repo.definition(record, connection)
        current = repo.state({'record': record, 'definition': definition}, connection)
        expected_group = (expected_state.get('groups') or {}).get(registration_set)
        actual_group = (current.get('groups') or {}).get(registration_set)
        if expected_group is None or actual_group != expected_group:
            return {'hss_state_reconciled': False, 'reconciliation_status': 'state_changed',
                    'message': 'Concurrent Cx change; registration state not overwritten'}
        group = deepcopy(actual_group)
        if reason_code == 3:
            if group.get('registered'):
                return {'hss_state_reconciled': False, 'reconciliation_status': 'active_registration'}
        else:
            registered = list(group.get('registered') or [])
            if private_identity not in registered:
                return {'hss_state_reconciled': False, 'reconciliation_status': 'identity_not_registered'}
            group['registered'] = [i for i in registered if i != private_identity]
            group['pending'] = [i for i in group.get('pending', []) if i != private_identity]
            group['known_private'] = [i for i in group.get('known_private', []) if i != private_identity]
        if group.get('registered'):
            group['state'] = 'registered'
        else:
            # After successful RTR, the targeted registration set is no longer
            # assigned to its old S-CSCF (reasons 0/2/3). Do not affect peers
            # or registered identities in other IRS groups.
            group.update(state='not_registered', registered=[], pending=[], known_private=[])
            for key in ('scscf', 'realm', 'peer', 'registered_at'):
                group.pop(key, None)
        current['groups'][registration_set] = group
        active = [g for g in current['groups'].values()
                  if g.get('registered') or g.get('state') == 'unregistered' or g.get('pending')]
        if not active:
            current.update(scscf=None, realm=None, peer=None, registered_at=None)
        else:
            # A single legacy assignment projection cannot represent different
            # S-CSCFs; preserve it only if it belongs to a remaining group.
            remaining_servers = {g.get('scscf') for g in active if g.get('scscf')}
            if remaining_servers and current.get('scscf') not in remaining_servers:
                if len(remaining_servers) == 1:
                    current['scscf'] = next(iter(remaining_servers))
                else:
                    current.update(scscf=None, realm=None, peer=None)
        repo.save(current, connection)
        return {'hss_state_reconciled': True, 'reconciliation_status': 'updated',
                'affected_registration_set': registration_set,
                'affected_private_identity': private_identity,
                'scscf_assignment_cleared': not bool(group.get('scscf')) and not group.get('registered'),
                'remaining_registered_impis': sum(len(g.get('registered') or []) for g in current['groups'].values()),
                'subscriber_deleted': False,
                'sip_contact_removal_verified': False}
