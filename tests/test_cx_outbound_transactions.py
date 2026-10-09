import json
from types import SimpleNamespace
from lib.cx_outbound_transactions import await_correlated_answer

def packet(request):
    return (bytes([1]) + (20).to_bytes(3, 'big') + bytes([0x80 if request else 0]) +
            (304).to_bytes(3, 'big') + (16777216).to_bytes(4, 'big') +
            (123).to_bytes(4, 'big') + (456).to_bytes(4, 'big')).hex()

class Redis:
    def __init__(self, answer): self.answer = answer
    def getList(self, **kwargs):
        return [json.dumps({'SenderIp':'10.0.0.1','SenderPort':3868,'InboundHex':self.answer})]

class Diameter:
    hostname = 'hss'
    def __init__(self, answer): self.redisMessaging = Redis(answer)
    def getPeerByHostname(self, hostname): return SimpleNamespace(IpAddress='10.0.0.1',Port=3868)
    def sendDiameterRequest(self, **kwargs): return packet(True)

def test_matching_rta():
    assert await_correlated_answer(Diameter(packet(False)), 'RTR', 'scscf', timeout=.1)['status'] == 'answer_received'

def test_wrong_rta_times_out():
    wrong = packet(False)[:-8] + '000001c9'
    assert await_correlated_answer(Diameter(wrong), 'RTR', 'scscf', timeout=.02, poll_interval=.005)['status'] == 'timeout'
