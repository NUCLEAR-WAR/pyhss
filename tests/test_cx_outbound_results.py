from lib.cx_outbound_results import evaluate_answer


def packet(request, avps=b'', command=304):
    flags = 0x80 if request else 0
    body = (bytes([1]) + (20 + len(avps)).to_bytes(3, 'big') + bytes([flags])
            + command.to_bytes(3, 'big') + (16777216).to_bytes(4, 'big')
            + bytes.fromhex('0102030405060708') + avps)
    return body.hex()


def avp(code, value):
    length = 8 + len(value)
    return (code.to_bytes(4, 'big') + bytes([0x40]) + length.to_bytes(3, 'big')
            + value + bytes((-length) % 4))


def test_success_rta():
    result = evaluate_answer(packet(True), packet(False, avp(268, (2001).to_bytes(4, 'big'))), 'RTR')
    assert result['status'] == 'success'


def test_error_ppa():
    result = evaluate_answer(packet(True, command=305), packet(False, avp(268, (5005).to_bytes(4, 'big')), command=305), 'PPR')
    assert result['status'] == 'diameter_error'


def test_missing_result_fails_closed():
    assert evaluate_answer(packet(True), packet(False), 'RTR')['status'] == 'malformed_answer'


def test_wrong_command_fails_closed():
    assert evaluate_answer(packet(True), packet(False, command=305), 'RTR')['status'] == 'mismatch'
