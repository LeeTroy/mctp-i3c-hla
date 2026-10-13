# End-to-end PLDM test: synthetic I3C LLA frames -> MCTP over I3C HLA with PLDM decoding on.
# Run: python3 test/test_pldm.py

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import HighLevelAnalyzer as hla  # noqa: E402
from test_spdm import Link, u16, u32  # noqa: E402

BASE, PLATFORM, BIOS, FRU, FWUP = 0x00, 0x02, 0x03, 0x04, 0x05


class PldmLink(Link):
    def __init__(self):
        super().__init__()
        self.iid = 0

    def request(self, pldm_type, command, payload=()):
        self.send([0x01, 0x80 | self.iid, pldm_type, command] + list(payload), False, 1)

    def response(self, pldm_type, command, cc=0, payload=()):
        self.send([0x01, self.iid, pldm_type, command, cc] + list(payload), True, 0)
        self.iid = (self.iid + 1) % 32
        self.tag = (self.tag + 1) % 8

    def exchange(self, pldm_type, command, request=(), cc=0, response=()):
        self.request(pldm_type, command, request)
        self.response(pldm_type, command, cc, response)


def run(link, kinds=('request', 'response', 'error'), **settings):
    for name, value in {'pec_mode': hla.PEC_PRESENT, 'address_filter': '', 'other_transfers': hla.OTHER_HIDE,
                        'spdm_mode': hla.SPDM_ALL, 'pldm_mode': hla.PLDM_ON, **settings}.items():
        setattr(hla.Hla, name, value)
    analyzer = hla.Hla()
    out = []
    for f in link.bus.frames:
        r = analyzer.decode(f)
        if r is not None and r.type in kinds:
            out.append(r)
    return out


def ver32(major, minor, update):
    return u32(0xF0F0F000 | major << 24 | minor << 16 | update << 8)


def version_str(text):
    return [1, len(text)], list(text.encode())


class Tests(unittest.TestCase):
    def test_base_discovery(self):
        link = PldmLink()
        link.exchange(BASE, 0x02, (), 0, [7])
        link.exchange(BASE, 0x04, (), 0, [0b00100101, 0, 0, 0, 0, 0, 0, 0])
        link.exchange(BASE, 0x03, u32(0) + [1, FWUP], 0, u32(0) + [0x05] + ver32(1, 1, 0) + u32(0x12345678))
        cmds = [0] * 32
        cmds[0x10 // 8] |= 1 << (0x10 % 8)
        cmds[0x15 // 8] |= 1 << (0x15 % 8)
        link.exchange(BASE, 0x05, [FWUP] + ver32(1, 1, 0), 0, cmds)

        out = run(link)
        self.assertEqual([f.type for f in out], ['request', 'response'] * 4)
        self.assertEqual(out[1].data['tid'], 7)
        self.assertIn('PLDM Base GetTID Rsp iid=0 | cc=SUCCESS | TID=7', out[1].data['summary'])
        self.assertEqual(out[3].data['types'], 'Base, Platform, FW Update')
        self.assertEqual(out[4].data['type_queried'], 'FW Update')
        self.assertEqual(out[5].data['versions'], '1.1.0')
        self.assertEqual(out[5].data['version_crc'], '0x12345678')
        self.assertEqual(out[6].data['type_version'], '1.1.0')
        self.assertEqual(out[7].data['commands'], 'RequestUpdate, RequestFirmwareData')
        self.assertEqual(out[1].data['protocol'], 'PLDM')
        self.assertIn('latency_ms', out[1].data)

    def test_firmware_update_flow(self):
        link = PldmLink()
        descriptors = u16(0x0000) + u16(2) + u16(0x1A03) + u16(0x0100) + u16(2) + u16(0x2500)
        link.exchange(FWUP, 0x01, (), 0, u32(len(descriptors)) + [2] + descriptors)

        hdr, text = version_str('v1.0')
        comp_hdr, comp_text = version_str('1.0.3')
        component = (u16(0x000A) + u16(0x1234) + [0] + u32(3) + comp_hdr + [0] * 8 + u32(0) + [0, 0] + [0] * 8 +
                     u16(0) + u32(0) + comp_text)
        link.exchange(FWUP, 0x02, (), 0, u32(0) + u16(1) + hdr + [0, 0] + text + component)

        hdr, text = version_str('v2.0')
        link.exchange(FWUP, 0x10, u32(256) + u16(1) + [1] + u16(0) + hdr + text, 0, u16(0) + [0])
        comp_hdr, comp_text = version_str('2.0.0')
        component = u16(0x000A) + u16(0x1234) + [0] + u32(4)
        link.exchange(FWUP, 0x13, [0x05] + component + comp_hdr + comp_text, 0, [0, 0])
        link.exchange(FWUP, 0x14, component + u32(4096) + u32(0) + comp_hdr + comp_text, 0,
                      [0, 0] + u32(0) + u16(0))

        # FD -> UA requests: the target sends the request, the controller answers.
        link.send([0x01, 0x80, FWUP, 0x15] + u32(0x100) + u32(256), True, 1)
        link.send([0x01, 0x00, FWUP, 0x15, 0x00] + [0xEE] * 256, False, 0)
        link.send([0x01, 0x81, FWUP, 0x16, 0x00], True, 1)
        link.send([0x01, 0x01, FWUP, 0x16, 0x00], False, 0)
        link.exchange(FWUP, 0x1B, (), 0, [3, 2, 0, 0, 50, 0] + u32(0))
        link.exchange(FWUP, 0x1A, [1], 0x80)

        out = run(link)
        s = [f.data['summary'] for f in out]
        self.assertIn('PCI Vendor ID=0x1A03; PCI Device ID=0x2500', s[1])
        self.assertEqual(out[3].data['active_version'], 'v1.0')
        self.assertEqual(out[3].data['component_0'], 'id 0x1234 active 1.0.3')
        self.assertIn('v2.0 components=1 max xfer=256', s[4])
        self.assertIn('StartAndEnd id 0x1234 2.0.0', s[6])
        self.assertIn('can be updated', s[7])
        self.assertIn('id 0x1234 2.0.0 size=4096', s[8])
        self.assertIn('offset=0x100 length=256', s[10])
        self.assertEqual(out[11].data['data_length'], 256)
        self.assertIn('(261 bytes)', s[11])
        self.assertEqual(out[11].data['src_eid'], 8)
        self.assertEqual(out[12].data['result'], 'success')
        self.assertIn('DOWNLOAD (was READY_XFER) | 50%', s[15])
        self.assertEqual(out[17].type, 'error')
        self.assertEqual(out[17].data['cc'], 'NOT_IN_UPDATE_MODE')
        for f in out:
            self.assertNotIn('error', f.data, f.data['summary'])

    def test_platform(self):
        link = PldmLink()
        link.exchange(PLATFORM, 0x11, u16(5) + [0], 0, [3, 0, 0, 1, 1, 1] + u16(0xFFF6))
        link.exchange(PLATFORM, 0x21, u16(6) + [0, 0], 0, [2, 0, 1, 1, 1, 0, 2, 1, 2])
        link.exchange(PLATFORM, 0x39, u16(9) + [2, 1, 3, 0, 0])
        link.exchange(PLATFORM, 0x51, u32(0) + u32(0) + [1] + u16(64) + u16(0), 0,
                      u32(2) + u32(0) + [0x05] + u16(12) + u32(1) + [1, 4] + u16(0) + u16(2) + [0, 0])
        link.send([0x01, 0x80, PLATFORM, 0x0A, 1, 7, 0x00] + u16(5) + [1, 2, 1], True, 1)
        link.send([0x01, 0x00, PLATFORM, 0x0A, 0x00, 0], False, 0)
        link.exchange(BIOS, 0x0C, (), 0, [0x30, 0x15, 0x09, 0x13, 0x10] + u16(0x2026))

        s = [f.data['summary'] for f in run(link)]
        self.assertIn('sensor 5 | reading=-10 | enabled', s[1])
        self.assertIn('sensor 6 | present=1,2', s[3])
        self.assertIn('effecter 9 states=3,-', s[4])
        self.assertIn('State Sensor | StartAndEnd 12 bytes, next 2', s[7])
        self.assertIn('TID=7 SensorEvent | sensor 5', s[8])
        self.assertIn('2026-10-13 09:15:30', s[11])

    def test_errors_datagram_and_off(self):
        link = PldmLink()
        link.exchange(BASE, 0x02, (), 0x05)                         # unsupported command
        link.send([0x01, 0xC3, PLATFORM, 0x0A, 1, 7, 6], False, 1)  # datagram request, no response
        link.send([0x01, 0x80, 0x45, 0x02], False, 1)               # header version 1
        link.send([0x01, 0x80], False, 1)                           # truncated

        out = run(link)
        self.assertEqual([f.type for f in out], ['request', 'error', 'request', 'error', 'error'])
        self.assertIn('cc=ERROR_UNSUPPORTED_PLDM_CMD', out[1].data['summary'])
        self.assertTrue(out[2].data['datagram'])
        self.assertIn('PlatformEventMessage Rq D', out[2].data['summary'])
        self.assertIn('header version 1', out[3].data['error'])
        self.assertIn('truncated', out[4].data['error'])

        off = run(link, kinds=('packet',), pldm_mode=hla.PLDM_OFF)
        self.assertEqual(off[0].data['detail'], 'Base GetTID Rq iid=0')
        self.assertEqual(off[1].data['detail'], 'Base GetTID Rsp iid=0 cc=ERROR_UNSUPPORTED_PLDM_CMD')


if __name__ == '__main__':
    unittest.main(verbosity=2)
