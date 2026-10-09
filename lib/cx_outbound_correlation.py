"""Strict Cx outbound response matching. No database side effects."""

CX_APPLICATION_ID = 16777216
COMMANDS = {'RTR': 304, 'PPR': 305}


def header(packet_hex):
    raw = bytes.fromhex(packet_hex)
    if len(raw) < 20 or raw[0] != 1:
        raise ValueError('Invalid Diameter header')
    length = int.from_bytes(raw[1:4], 'big')
    if length != len(raw):
        raise ValueError('Invalid Diameter message length')
    return {
        'request': bool(raw[4] & 0x80),
        'command': int.from_bytes(raw[5:8], 'big'),
        'application': int.from_bytes(raw[8:12], 'big'),
        'hop_by_hop': raw[12:16],
        'end_to_end': raw[16:20],
    }


def matches_answer(request_hex, answer_hex, operation):
    """Match response by Cx application, command and both Diameter identifiers."""
    if operation not in COMMANDS:
        raise ValueError('Unsupported Cx operation')
    req, ans = header(request_hex), header(answer_hex)
    return (req['request'] and not ans['request']
            and req['application'] == ans['application'] == CX_APPLICATION_ID
            and req['command'] == ans['command'] == COMMANDS[operation]
            and req['hop_by_hop'] == ans['hop_by_hop']
            and req['end_to_end'] == ans['end_to_end'])
