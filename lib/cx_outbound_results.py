"""Fail-closed Cx RTA/PPA result evaluation (RFC 6733 AVP framing).

This module never changes subscriber state. It requires a previously correlated
answer and checks the mandatory Result-Code or Experimental-Result AVPs.
"""
from .cx_outbound_correlation import matches_answer


def _avps(raw):
    offset = 0
    while offset < len(raw):
        if len(raw) - offset < 8:
            raise ValueError('Truncated AVP header')
        code = int.from_bytes(raw[offset:offset + 4], 'big')
        flags = raw[offset + 4]
        length = int.from_bytes(raw[offset + 5:offset + 8], 'big')
        header_size = 12 if flags & 0x80 else 8
        if length < header_size or offset + length > len(raw):
            raise ValueError('Invalid AVP length')
        vendor = int.from_bytes(raw[offset + 8:offset + 12], 'big') if flags & 0x80 else 0
        yield code, vendor, raw[offset + header_size:offset + length]
        offset += (length + 3) & ~3
    if offset != len(raw):
        raise ValueError('Invalid AVP padding')


def evaluate_answer(request_hex, answer_hex, operation):
    """Return status/result after strict matching; never interpret timeout as success."""
    if not matches_answer(request_hex, answer_hex, operation):
        return {'status': 'mismatch', 'operation': operation}
    raw = bytes.fromhex(answer_hex)
    try:
        result_codes = []
        experimental = []
        for code, vendor, value in _avps(raw[20:]):
            if code == 268 and vendor == 0:
                if len(value) != 4:
                    raise ValueError('Malformed Result-Code')
                result_codes.append(int.from_bytes(value, 'big'))
            elif code == 297 and vendor == 0:
                vendor_ids, codes = [], []
                for nested_code, nested_vendor, nested_value in _avps(value):
                    if len(nested_value) != 4:
                        raise ValueError('Malformed Experimental-Result')
                    if nested_code == 266 and nested_vendor == 0:
                        vendor_ids.append(int.from_bytes(nested_value, 'big'))
                    if nested_code == 298 and nested_vendor == 0:
                        codes.append(int.from_bytes(nested_value, 'big'))
                if len(vendor_ids) != 1 or len(codes) != 1:
                    raise ValueError('Incomplete Experimental-Result')
                experimental.append((vendor_ids[0], codes[0]))
        if len(result_codes) + len(experimental) != 1:
            raise ValueError('Missing or ambiguous Diameter result')
        if result_codes:
            code = result_codes[0]
            return {'status': 'success' if code == 2001 else 'diameter_error',
                    'operation': operation, 'result_code': code}
        vendor, code = experimental[0]
        return {'status': 'diameter_error', 'operation': operation,
                'experimental_vendor_id': vendor, 'experimental_result_code': code}
    except (ValueError, TypeError) as exc:
        return {'status': 'malformed_answer', 'operation': operation, 'reason': str(exc)}
