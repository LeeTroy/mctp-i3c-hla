# End-to-end SPDM test: synthetic I3C LLA frames -> MCTP over I3C HLA with SPDM decoding on.
# Run: python3 test/test_spdm.py

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import HighLevelAnalyzer as hla  # noqa: E402
from test_hla import Bus, packet  # noqa: E402

TARGET = 0x09
BMC_EID, DEV_EID = 8, 9


class Link:
    """Sends MCTP messages over I3C, split into 64-byte packets, with a pending-read IBI before each response."""

    def __init__(self):
        self.bus = Bus()
        self.tag = 0

    def send(self, message, from_target, tag_owner):
        rnw = 1 if from_target else 0
        src, dest = (DEV_EID, BMC_EID) if from_target else (BMC_EID, DEV_EID)
        chunks = [message[i:i + 60] for i in range(0, len(message), 60)]
        if from_target:
            self.bus.read(TARGET, [0xAE])
            self.bus.stop()
        for seq, chunk in enumerate(chunks):
            pkt = packet(TARGET, rnw, dest, src, seq == 0, seq == len(chunks) - 1, seq % 4, tag_owner, self.tag, chunk)
            if from_target:
                self.bus.write(0x7E, [])
                self.bus.read(TARGET, pkt)
            else:
                self.bus.write(TARGET, pkt)
            self.bus.stop()

    def request(self, spdm_msg):
        self.send([0x05] + spdm_msg, False, 1)

    def response(self, spdm_msg):
        self.send([0x05] + spdm_msg, True, 0)
        self.tag = (self.tag + 1) % 8


def run(link, kinds=('request', 'response', 'error', 'secured'), **settings):
    for name, value in {'pec_mode': hla.PEC_PRESENT, 'address_filter': '', 'other_transfers': hla.OTHER_HIDE,
                        'spdm_mode': hla.SPDM_ALL, 'spdm_columns': hla.SPDM_COLUMNS_FULL, **settings}.items():
        setattr(hla.Hla, name, value)
    analyzer = hla.Hla()
    out = []
    for f in link.bus.frames:
        r = analyzer.decode(f)
        if r is not None and r.type in kinds:
            out.append(r)
    return out


def u16(v):
    return [v & 0xFF, v >> 8]


def u32(v):
    return [(v >> (8 * i)) & 0xFF for i in range(4)]


def der_cert(n):
    body = [0xAA] * n
    return [0x30, 0x82] + [n >> 8, n & 0xFF] + body


class Tests(unittest.TestCase):
    def test_full_flow(self):
        link = Link()
        V = 0x12
        link.request([0x10, 0x84, 0, 0])
        link.response([0x10, 0x04, 0, 0, 0, 2] + u16(0x1100) + u16(0x1200))
        link.request([V, 0xE1, 0, 0, 0, 12, 0, 0] + u32(0x0000B2C6) + u32(4096) + u32(4096))
        link.response([V, 0x61, 0, 0, 0, 12, 0, 0] + u32(0x0000F3D6) + u32(4096) + u32(4096))
        req_algs = [2, 0x20] + u16(0x0018) + [3, 0x20] + u16(0x0002) + [4, 0x20] + u16(0x0090) + [5, 0x20] + u16(1)
        link.request([V, 0xE3, 4, 0] + u16(48) + [1, 2] + u32(0x90) + u32(0x02) + [0] * 12 + [0, 0, 0, 0] + req_algs)
        rsp_algs = [2, 0x20] + u16(0x0010) + [3, 0x20] + u16(0x0002) + [4, 0x20] + u16(0x0080) + [5, 0x20] + u16(1)
        link.response([V, 0x63, 4, 0] + u16(52) + [1, 2] + u32(0x04) + u32(0x80) + u32(0x02) + [0] * 12 +
                      [0, 0, 0, 0] + rsp_algs)
        link.request([V, 0x81, 0, 0])
        link.response([V, 0x01, 0, 0x01] + [0x11] * 48)

        root_hash = [0x22] * 48
        chain_body = root_hash + der_cert(100) + der_cert(150)
        chain = u16(4 + len(chain_body)) + [0, 0] + chain_body
        link.request([V, 0x82, 0, 0] + u16(0) + u16(200))
        link.response([V, 0x02, 0, 0] + u16(200) + u16(len(chain) - 200) + chain[:200])
        link.request([V, 0x82, 0, 0] + u16(200) + u16(200))
        rest = chain[200:]
        link.response([V, 0x02, 0, 0] + u16(len(rest)) + u16(0) + rest)

        link.request([V, 0xE0, 0x01, 0xFF] + [0x33] * 32 + [0])
        block = [0x02, 0x01] + u16(3 + 48) + [0x01] + u16(48) + [0x44] * 48
        link.response([V, 0x60, 0, 0, 1] + [len(block), 0, 0] + block + [0x55] * 32 + u16(0) + [0x66] * 96)

        link.request([V, 0xE4, 0, 0] + u16(0xFFFF) + [0, 0] + [0x77] * 32 + [0x88] * 96 + u16(0))
        link.response([V, 0x64, 0, 0] + u16(0xFFFE) + [0, 0] + [0x99] * 32)
        link.send([0x06] + u32(0xFFFEFFFF) + u16(0) + u16(20) + [0xAB] * 20, False, 1)
        link.request([V, 0xE5, 0, 0] + [0] * 48)
        link.response([V, 0x7F, 0x42, 0, 10, 0xE5, 3, 2])

        out = run(link)
        self.assertEqual(len(out), 19)
        self.assertEqual(out[1].data['versions'], '1.1.0, 1.2.0')
        self.assertIn('CERT CHAL MEAS=2 ENCRYPT MAC MUT_AUTH KEY_EX', out[3].data['capabilities'])
        alg = out[5].data
        self.assertEqual((alg['base_asym'], alg['base_hash'], alg['meas_hash']), ('ECDSA_P384', 'SHA384', 'SHA384'))
        self.assertEqual((alg['dhe'], alg['aead'], alg['keyschedule']), ('secp384r1', 'AES_256_GCM', 'SPDM'))
        self.assertEqual(out[7].data['digest_slot0'], ' '.join(['11'] * 48))
        self.assertEqual(out[11].data['cert_count'], 2)
        self.assertEqual(out[13].data['signature_len'], 96)
        self.assertIn('#2 MutableFW 4444', out[13].data['summary'])
        self.assertEqual(out[15].data['session_id'], '0xFFFEFFFF')
        self.assertEqual(out[16].type, 'secured')
        self.assertIn('(KEY_EXCHANGE)', out[16].data['summary'])
        self.assertEqual(out[18].type, 'error')
        self.assertIn('ResponseNotReady', out[18].data['summary'])
        self.assertEqual(out[18].data['not_ready_request'], 'FINISH')
        for f in out:
            self.assertNotIn('truncated', f.data.get('error', ''), f.data['summary'])

    def test_mismatched_response_and_secured_as_packet(self):
        link = Link()
        link.request([0x12, 0x81, 0, 0])
        link.response([0x12, 0x04, 0, 0, 0, 0])
        link.send([0x06] + u32(1) + u16(0) + u16(2) + [0, 0], False, 1)
        out = run(link, kinds=('request', 'response', 'error', 'secured', 'packet'), spdm_mode=hla.SPDM_ONLY)
        self.assertEqual([f.type for f in out], ['request', 'error', 'packet'])
        self.assertIn('response to GET_DIGESTS', out[1].data['error'])
        self.assertEqual(out[2].data['msg_type'], 'Secured')

    def test_multi_packet_message(self):
        link = Link()
        link.request([0x12, 0xE4, 0, 0] + u16(0xFFFF) + [0, 0] + [0x77] * 100)
        out = run(link, kinds=('request', 'packet'))
        self.assertEqual([f.type for f in out], ['packet', 'request'])
        self.assertIn('SPDM | KEY_EXCHANGE', out[0].data['summary'])
        self.assertEqual(out[1].data['name'], 'KEY_EXCHANGE')
        self.assertEqual(out[1].data['message_len'], 1 + 4 + 4 + 100)
        self.assertEqual((out[1].data['src_eid'], out[1].data['dest_eid']), ('0x08', '0x09'))
        self.assertIn('(109 bytes)', out[1].data['summary'])
        self.assertIn('PEC OK', out[1].data['summary'])

    def test_pec_error_and_off(self):
        link = Link()
        link.request([0x10, 0x84, 0, 0])
        frames = link.bus.frames
        last_write = max(i for i, f in enumerate(frames) if f.type == 'write')
        frames[last_write].data['data'] ^= 0xFF
        out = run(link)
        self.assertEqual(out[0].type, 'error')
        self.assertEqual(out[0].data['name'], 'GET_VERSION')
        self.assertIn('PEC', out[0].data['error'])

        out = run(link, kinds=('packet',), spdm_mode=hla.SPDM_OFF)
        self.assertEqual(out[0].data['detail'], 'v1.0 GET_VERSION')

    def test_simple_columns(self):
        link = Link()
        link.request([0x12, 0xE4, 0x02, 0x01] + u16(0xFFFF) + [0, 0] + [0x77] * 100)
        link.response([0x12, 0x64, 0, 0] + u16(0xFFFE) + [0, 0] + [0x99] * 32)
        link.send([0x06] + u32(0xFFFEFFFF) + u16(0) + u16(20) + [0xAB] * 20, False, 1)
        link.request([0x12, 0xE5, 0, 0] + [0] * 48)
        link.response([0x12, 0x7F, 0x42, 0, 10, 0xE5, 3, 2])
        frames = link.bus.frames
        last_write = max(i for i, f in enumerate(frames) if f.type == 'write')
        frames[last_write].data['data'] ^= 0xFF  # PEC error on the FINISH request

        kinds = ('spdm_request', 'spdm_response', 'spdm_error', 'spdm_secured')
        out = run(link, kinds=kinds, spdm_columns=hla.SPDM_COLUMNS_SIMPLE)
        self.assertEqual([f.type for f in out],
                         ['spdm_request', 'spdm_response', 'spdm_secured', 'spdm_error', 'spdm_error'])
        self.assertEqual(out[0].data, {'version': '1.2', 'message_type': 'KEY_EXCHANGE', 'param1': '0x02',
                                       'param2': '0x01', 'message_length': 108})
        self.assertEqual(out[1].data['message_type'], 'KEY_EXCHANGE_RSP')
        self.assertEqual(out[2].data, {'message_type': 'SECURED_MESSAGE', 'message_length': 28})
        self.assertEqual(out[3].data['message_type'], 'FINISH')
        self.assertEqual(out[4].data['param1'], '0x42')
        for f in out:
            self.assertLessEqual(set(f.data), {'version', 'message_type', 'param1', 'param2', 'message_length'})
        for kind in kinds:
            self.assertIn(kind, hla.Hla.result_types)


if __name__ == '__main__':
    unittest.main(verbosity=2)
