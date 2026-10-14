# Feeds synthetic MIPI I3C LLA and XyphroLabs I3C LLA frames to the HLA and checks the decoded output.
# Run: python3 test/test_hla.py

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from saleae.analyzers import AnalyzerFrame  # noqa: E402
import HighLevelAnalyzer as hla  # noqa: E402


class Bus:
    """Builds the frame sequence the I3C LLA emits."""

    def __init__(self):
        self.frames = []
        self.t = 0
        self.open = False

    def add(self, type, **data):
        self.frames.append(AnalyzerFrame(type, self.t, self.t + 1, data))
        self.t += 2

    def start(self):
        self.add('restart' if self.open else 'start')
        self.open = True

    def stop(self):
        self.add('stop')
        self.open = False

    def write(self, address, data, ack=True):
        self.start()
        self.add('address', address=address, read=False, ack=ack)
        for b in data:
            self.add('write', data=b, parity_ok=True)

    def read(self, address, data):
        self.start()
        self.add('address', address=address, read=True, ack=True)
        for i, b in enumerate(data):
            self.add('read', data=b, more=i < len(data) - 1)

    # HDR-DDR, as the LLA reports it: one frame per Word.

    def enter_ddr(self):
        self.ccc(0x20)

    def ddr(self, address, command, read, data, crc_ok=True, terminate=False, ccc_selector=False):
        frame = {'read': read, 'command': command | (0x80 if read else 0), 'address': address, 'parity_ok': True}
        if ccc_selector:
            frame['ccc_selector'] = True
        self.add('ddr_command', **frame)
        if len(data) % 2:
            data = list(data) + [0x00]
        for i in range(0, len(data), 2):
            self.add('ddr_data', data=data[i] << 8 | data[i + 1], read=read, parity_ok=True)
        if terminate:
            self.add('ddr_end', read=read)
        self.add('ddr_crc', crc=0x0A, expected=0x0A if crc_ok else 0x0B, crc_ok=crc_ok)

    def ddr_ccc(self, code):
        self.add('ddr_command', read=False, command=0, address=0x7E, parity_ok=True)
        self.add('ddr_ccc', data=code << 8, ccc_code=code, parity_ok=True)
        self.add('ddr_crc', crc=0x0A, expected=0x0A, crc_ok=True)

    def ddr_nack(self, address, read):
        self.add('ddr_command', read=read, command=0xA0 if read else 0x20, address=address, parity_ok=True)
        self.add('ddr_nack', read=read)

    def hdr_restart(self):
        self.add('hdr_restart')

    def hdr_exit(self):
        self.add('hdr_exit')
        self.stop()

    def ccc(self, code, data=()):
        self.start()
        self.add('address', address=0x7E, read=False, ack=True)
        self.add('ccc', data=code, parity_ok=True)
        for b in data:
            self.add('write', data=b, parity_ok=True)


class XyphroBus(Bus):
    """Builds the frame sequence the XyphroLabs I3C LLA emits: raw T-bits, preambles, parity bits and CRC-5."""

    def write(self, address, data, ack=True):
        self.start()
        self.add('address', address=address, read=False, ack=ack)
        for b in data:
            t_bit = 0 if hla.odd_parity(b) else 1
            self.add('data', data=b, ack=t_bit == 0)

    def read(self, address, data):
        self.start()
        self.add('address', address=address, read=True, ack=True)
        for i, b in enumerate(data):
            self.add('data', data=b, ack=i == len(data) - 1)  # T-bit 1 = more data

    def ccc(self, code, data=()):
        self.write(0x7E, [code] + list(data))

    def ddr_word(self, type, word, preamble, **fields):
        key = 'address&offset' if type == 'DDR_CMD' else 'data'
        self.add(type, **{key: word, 'preamble': preamble, 'parity': hla.ddr_parity(word)}, **fields)

    def ddr_command_word(self, address, command, read):
        word = (command | (0x80 if read else 0)) << 8 | address << 1
        self.ddr_word('DDR_CMD', word, 0b01)
        return hla.ddr_crc5(0x1F, word)

    def ddr(self, address, command, read, data, crc_ok=True, terminate=False, ccc_selector=False):
        crc = self.ddr_command_word(address, command, read)
        if len(data) % 2:
            data = list(data) + [0x00]
        for i in range(0, len(data), 2):
            word = data[i] << 8 | data[i + 1]
            self.ddr_word('DDR_DATA', word, 0b10 if i == 0 else 0b11)
            crc = hla.ddr_crc5(crc, word)
        if terminate:
            # Preamble 2'b10, then the CRC Word without its preamble, which the LLA reads as a Data Word.
            self.ddr_word('DDR_DATA', 0x3000 | crc << 7, 0b10)
            self.ddr_word('DDR_DATA', 0xFFFF, 0b11)
            return
        self.add('DDR_crc', preamble=0b01, token=0xC, crc=crc if crc_ok else crc ^ 1)

    def ddr_ccc(self, code):
        crc = self.ddr_command_word(0x7E, 0, False)
        self.ddr_word('DDR_DATA', code << 8, 0b10)
        self.add('DDR_crc', preamble=0b01, token=0xC, crc=hla.ddr_crc5(crc, code << 8))

    def ddr_nack(self, address, read):
        self.ddr_command_word(address, 0x20, read)
        self.ddr_word('DDR_DATA', 0xFFFF, 0b11)

    def hdr_restart(self):
        self.add('HDR_restart')

    def hdr_exit(self):
        self.add('HDR_exit')
        self.stop()


def packet(address, rnw, dest, src, som, eom, seq, to, tag, payload, pec=True):
    flags = (som << 7) | (eom << 6) | (seq << 4) | (to << 3) | tag
    pkt = [0x01, dest, src, flags] + list(payload)
    if pec:
        pkt.append(hla.crc8([(address << 1) | rnw] + pkt))
    return pkt


def run(bus, **settings):
    for name, value in {'pec_mode': hla.PEC_PRESENT, 'address_filter': '',
                        'other_transfers': hla.OTHER_HIDE, 'spdm_mode': hla.SPDM_OFF,
                        'pldm_mode': hla.PLDM_OFF, **settings}.items():
        setattr(hla.Hla, name, value)
    analyzer = hla.Hla()
    out = []
    for f in bus.frames:
        r = analyzer.decode(f)
        if r is not None:
            out.extend(r if isinstance(r, list) else [r])
    return out


class Tests(unittest.TestCase):
    Bus = Bus

    def test_crc8(self):
        # CRC-8/SMBUS check value
        self.assertEqual(hla.crc8(b'123456789'), 0xF4)

    def test_control_request_and_response(self):
        bus = self.Bus()
        # Get Endpoint ID request, controller (EID 8) -> target 0x09 (EID 9)
        bus.write(0x09, packet(0x09, 0, 9, 8, 1, 1, 0, 1, 2, [0x00, 0x81, 0x02]))
        bus.stop()
        # IBI pending read, then private read of the response
        bus.read(0x09, [0xAE])
        bus.stop()
        bus.write(0x7E, [])
        bus.read(0x09, packet(0x09, 1, 8, 9, 1, 1, 0, 0, 2, [0x00, 0x01, 0x02, 0x00, 0x09, 0x00, 0x00]))
        bus.stop()

        out = run(bus)
        self.assertEqual([f.type for f in out], ['packet', 'ibi', 'packet'])
        rq, ibi, rsp = out
        self.assertEqual(rq.data['detail'], 'Get Endpoint ID Rq iid=1')
        self.assertTrue(rq.data['pec_ok'])
        self.assertEqual((rq.data['src_eid'], rq.data['dest_eid'], rq.data['tag'], rq.data['to']),
                         ('0x08', '0x09', 2, True))
        self.assertIn('pending read', ibi.data['summary'])
        self.assertEqual(rsp.data['detail'], 'Get Endpoint ID Rsp iid=1 cc=SUCCESS')
        self.assertEqual(rsp.data['direction'], 'read')
        self.assertNotIn('error', rsp.data)

    def test_multi_packet_reassembly(self):
        msg = [0x05, 0x12, 0x84] + list(range(100))
        chunks = [msg[0:60], msg[60:]]
        bus = self.Bus()
        bus.write(0x10, packet(0x10, 0, 20, 8, 1, 0, 1, 1, 0, chunks[0]))
        bus.stop()
        bus.write(0x10, packet(0x10, 0, 20, 8, 0, 1, 2, 1, 0, chunks[1]))
        bus.stop()

        first, last = run(bus)
        self.assertEqual(first.data['msg_type'], 'SPDM')
        self.assertNotIn('message', first.data)
        self.assertEqual(last.data['message_len'], len(msg))
        self.assertEqual(last.data['detail'], 'v1.2 GET_VERSION')
        self.assertNotIn('error', last.data)

    def test_errors(self):
        bus = self.Bus()
        bad = packet(0x09, 0, 9, 8, 1, 1, 0, 1, 0, [0x00, 0x81, 0x02])
        bad[-1] ^= 0xFF
        bus.write(0x09, bad)
        bus.stop()
        bus.write(0x09, packet(0x09, 0, 9, 8, 0, 1, 1, 1, 1, [0xAA]))  # middle/end without SOM
        bus.stop()
        bus.write(0x09, packet(0x09, 0, 9, 8, 1, 0, 0, 1, 3, [0x01, 0x80, 0x02, 0x04]))
        bus.stop()
        bus.write(0x09, packet(0x09, 0, 9, 8, 0, 1, 2, 1, 3, [0xAA]))  # seq skips 1
        bus.stop()

        pec, no_som, _, bad_seq = run(bus)
        self.assertFalse(pec.data['pec_ok'])
        self.assertIn('PEC', pec.data['error'])
        self.assertIn('no SOM', no_som.data['error'])
        self.assertIn('seq 2, expected 1', bad_seq.data['error'])

    def test_ccc_and_non_mctp_ignored(self):
        bus = self.Bus()
        bus.ccc(0x06)                       # broadcast RSTDAA
        bus.stop()
        bus.ccc(0x90)                       # direct GETPID
        bus.read(0x09, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        bus.stop()
        bus.write(0x09, [0x55, 0x66, 0x77, 0x88, 0x99])  # not MCTP
        bus.stop()
        bus.write(0x0A, [0x01], ack=False)  # NACKed
        bus.stop()
        self.assertEqual(run(bus), [])
        shown = run(bus, other_transfers=hla.OTHER_SHOW)
        self.assertEqual([f.type for f in shown], ['i3c'])

    def test_no_pec_and_address_filter(self):
        bus = self.Bus()
        bus.write(0x09, packet(0x09, 0, 9, 8, 1, 1, 0, 1, 0, [0x01, 0x80, 0x02, 0x04], pec=False))
        bus.stop()
        bus.write(0x0B, packet(0x0B, 0, 11, 8, 1, 1, 0, 1, 0, [0x01, 0x80, 0x02, 0x04], pec=False))
        bus.stop()
        out = run(bus, pec_mode=hla.PEC_ABSENT, address_filter='0x0B')
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].data['address'], 0x0B)
        self.assertEqual(out[0].data['detail'], 'Platform SetEventReceiver Rq iid=0')
        self.assertNotIn('pec', out[0].data)


class DdrTests(unittest.TestCase):
    Bus = Bus

    def test_mctp_over_ddr(self):
        bus = self.Bus()
        bus.enter_ddr()
        # Get Endpoint ID request: 7 packet bytes + PEC = 8 bytes, no padding
        bus.ddr(0x09, 0x20, False, packet(0x09, 0, 9, 8, 1, 1, 0, 1, 2, [0x00, 0x81, 0x02]))
        bus.hdr_restart()
        # Response: 11 packet bytes + PEC = 12 bytes; then a 9-byte packet padded to 10
        bus.ddr(0x09, 0x20, True, packet(0x09, 1, 8, 9, 1, 1, 0, 0, 2, [0x00, 0x01, 0x02, 0x00, 0x09, 0x00, 0x00]))
        bus.hdr_restart()
        bus.ddr(0x09, 0x20, False, packet(0x09, 0, 9, 8, 1, 1, 0, 1, 3, [0x00, 0x82, 0x02, 0x00]))
        bus.hdr_exit()

        rq, rsp, padded = run(bus)
        self.assertEqual(rq.data['detail'], 'Get Endpoint ID Rq iid=1')
        self.assertEqual(rq.data['mode'], 'HDR-DDR')
        self.assertEqual(rq.data['ddr_command'], 0x20)
        self.assertTrue(rq.data['summary'].startswith('DDR W 0x09 | EID 8->9'))
        self.assertTrue(rq.data['pec_ok'])
        self.assertEqual(rsp.data['detail'], 'Get Endpoint ID Rsp iid=1 cc=SUCCESS')
        self.assertEqual(rsp.data['ddr_command'], 0xA0)
        self.assertTrue(rsp.data['summary'].startswith('DDR R 0x09'))
        self.assertTrue(padded.data['pec_ok'])
        self.assertEqual(padded.data['payload'], '00 82 02 00')
        for f in (rq, rsp, padded):
            self.assertNotIn('error', f.data, f.data['summary'])

    def test_ddr_errors(self):
        bus = self.Bus()
        bus.enter_ddr()
        bus.ddr(0x09, 0x20, False, packet(0x09, 0, 9, 8, 1, 1, 0, 1, 2, [0x00, 0x81, 0x02]), crc_ok=False)
        bus.hdr_restart()
        bus.ddr(0x09, 0x20, True, packet(0x09, 1, 8, 9, 1, 1, 0, 0, 2, [0x00, 0x81, 0x02]), terminate=True)
        bus.hdr_restart()
        bus.ddr_nack(0x09, True)
        bus.hdr_exit()

        crc, terminated = run(bus)
        self.assertRegex(crc.data['error'], r'CRC-5 0x[0-9A-F]{2} != 0x[0-9A-F]{2}')
        self.assertIn('terminated by Controller', terminated.data['error'])

    def test_ddr_ccc_and_other_transfers(self):
        bus = self.Bus()
        bus.enter_ddr()
        bus.ddr_ccc(0x00)  # ENEC broadcast
        bus.hdr_restart()
        bus.ddr_ccc(0x90)  # direct GETSTATUS: Selector Word to the target, then the target's data
        bus.hdr_restart()
        bus.ddr(0x09, 0x00, True, [0x01, 0x00, 0x00, 0x00, 0x00, 0x00], ccc_selector=True)
        bus.hdr_restart()
        bus.ddr_ccc(0x1F)  # end of CCC modality
        bus.hdr_restart()
        bus.ddr(0x09, 0x2A, False, [0x55, 0x66, 0x77])  # not MCTP
        bus.hdr_exit()

        self.assertEqual(run(bus), [])
        shown = run(bus, other_transfers=hla.OTHER_SHOW)
        self.assertEqual([f.type for f in shown], ['i3c'])
        self.assertEqual(shown[0].data['summary'], 'DDR W 0x09 cmd=0x2A: 55 66 77 00')


class XyphroTests(Tests):
    Bus = XyphroBus


class XyphroDdrTests(DdrTests):
    Bus = XyphroBus

    def test_ddr_parity_and_crc_checked(self):
        bus = self.Bus()
        bus.enter_ddr()
        bus.ddr(0x09, 0x20, False, packet(0x09, 0, 9, 8, 1, 1, 0, 1, 2, [0x00, 0x81, 0x02]))
        bus.hdr_exit()
        bad = [f for f in bus.frames if f.type == 'DDR_DATA'][1]
        bad.data['parity'] ^= 1
        (rq,) = run(bus)
        self.assertIn('parity', rq.data['error'])
        self.assertNotIn('CRC', rq.data['error'])

    def test_sdr_write_parity_checked(self):
        bus = self.Bus()
        bus.write(0x09, packet(0x09, 0, 9, 8, 1, 1, 0, 1, 2, [0x00, 0x81, 0x02]))
        bus.stop()
        bus.frames[3].data['ack'] = not bus.frames[3].data['ack']
        (rq,) = run(bus)
        self.assertIn('parity', rq.data['error'])

    def test_entdaa_ignored(self):
        bus = self.Bus()
        bus.ccc(0x07)
        bus.start()
        bus.add('address', address=0x7E, read=True, ack=True)
        for b in (0x04, 0x6A, 0x00, 0x00, 0x00, 0x01, 0xC6, 0x00):
            bus.add('entdaaPL', address=b)
        bus.add('data', data=0x09 << 1, ack=True)
        bus.stop()
        bus.write(0x09, packet(0x09, 0, 9, 8, 1, 1, 0, 1, 2, [0x00, 0x81, 0x02]))
        bus.stop()
        self.assertEqual([f.data['detail'] for f in run(bus)], ['Get Endpoint ID Rq iid=1'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
