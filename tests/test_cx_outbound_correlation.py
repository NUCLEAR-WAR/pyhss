import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from cx_outbound_correlation import matches_answer


def packet(command=304, app=16777216, flags=0x80, hop=1, end=2):
    return (bytes([1]) + (20).to_bytes(3, 'big') + bytes([flags])
            + command.to_bytes(3, 'big') + app.to_bytes(4, 'big')
            + hop.to_bytes(4, 'big') + end.to_bytes(4, 'big')).hex()


def test_rta_match():
    assert matches_answer(packet(), packet(flags=0), 'RTR')
    assert not matches_answer(packet(), packet(flags=0, hop=3), 'RTR')
    assert not matches_answer(packet(), packet(flags=0, end=3), 'RTR')
    assert not matches_answer(packet(), packet(flags=0, command=305), 'RTR')
    assert not matches_answer(packet(), packet(flags=0, app=16777217), 'RTR')
    assert not matches_answer(packet(), packet(), 'RTR')


def test_ppa_match():
    assert matches_answer(packet(command=305), packet(command=305, flags=0), 'PPR')
