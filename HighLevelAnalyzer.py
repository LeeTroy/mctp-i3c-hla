# MCTP over I3C (DMTF DSP0233) high level analyzer for Saleae Logic 2.
#
# Input: frames from the MIPI I3C low level analyzer
#   start, restart, stop, hdr, hdr_exit, hdr_restart
#   address  {address, read, ack}
#   ccc      {data, parity_ok, ccc}
#   write    {data, parity_ok}
#   read     {data, more}
#   HDR-DDR: ddr_command {read, command, address, parity_ok, ccc_selector}, ddr_data {data (16 bits), read,
#            parity_ok}, ddr_crc {crc, expected, crc_ok}, ddr_ccc, ddr_nack, ddr_end, ddr_error
#
# An MCTP packet is carried in one I3C private write (controller -> target) or private read
# (target -> controller). A target announces a pending packet with an IBI whose mandatory data
# byte is 0xAE. DSP0233 only defines SDR transfers, so for HDR-DDR the analyzer assumes the same packet in the
# Data Words of a DDR Write / Read Command (first byte in bits 15:8), with the same PEC, and an odd-length packet
# padded with one 0x00 byte as I3C requires. Packet layout:
#   [0] rsvd[7:4] | header version[3:0] (= 1)
#   [1] destination EID
#   [2] source EID
#   [3] SOM[7] | EOM[6] | pkt seq[5:4] | TO[3] | msg tag[2:0]
#   [4] IC[7] | message type[6:0]          (SOM packet only)
#   ... payload
#   [n] PEC: CRC-8 (x^8 + x^2 + x + 1) over (address << 1 | RnW) and all packet bytes
#
# Optionally decodes PLDM (DSP0240 / DSP0241 and the PLDM type specs) and SPDM (DSP0274 / DSP0275) on top of MCTP. The decoded message is reported on the frame of the
# EOM packet, as Logic 2 runs an HLA on a single input analyzer and its frames must not overlap.
#   MCTP message type 0x05 = SPDM:
#     [0] SPDMVersion  [1] RequestResponseCode  [2] Param1  [3] Param2  [4..] payload
#   MCTP message type 0x06 = Secured SPDM (DSP0277 / DSP0275):
#     [0..3] SessionID  [4..5] SequenceNumber  [6..7] Length  [8..] encrypted data + MAC

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, ChoicesSetting

MCTP_HEADER_VERSION = 0x01
MDB_PENDING_READ = 0xAE
I3C_BROADCAST_ADDRESS = 0x7E

MESSAGE_TYPES = {
    0x00: 'Control',
    0x01: 'PLDM',
    0x02: 'NC-SI',
    0x03: 'Ethernet',
    0x04: 'NVMe-MI',
    0x05: 'SPDM',
    0x06: 'Secured',
    0x07: 'CXL FM-API',
    0x08: 'CXL CCI',
    0x7E: 'Vendor PCI',
    0x7F: 'Vendor IANA',
}

CONTROL_COMMANDS = {
    0x01: 'Set Endpoint ID',
    0x02: 'Get Endpoint ID',
    0x03: 'Get Endpoint UUID',
    0x04: 'Get MCTP Version Support',
    0x05: 'Get Message Type Support',
    0x06: 'Get Vendor Defined Message Support',
    0x07: 'Resolve Endpoint ID',
    0x08: 'Allocate Endpoint IDs',
    0x09: 'Routing Information Update',
    0x0A: 'Get Routing Table Entries',
    0x0B: 'Prepare for Endpoint Discovery',
    0x0C: 'Endpoint Discovery',
    0x0D: 'Discovery Notify',
    0x0E: 'Get Network ID',
    0x0F: 'Query Hop',
    0x10: 'Resolve UUID',
    0x11: 'Query Rate Limit',
    0x12: 'Request TX Rate Limit',
    0x13: 'Update Rate Limit',
    0x14: 'Query Supported Interfaces',
}

CONTROL_COMPLETION_CODES = {
    0x00: 'SUCCESS',
    0x01: 'ERROR',
    0x02: 'ERROR_INVALID_DATA',
    0x03: 'ERROR_INVALID_LENGTH',
    0x04: 'ERROR_NOT_READY',
    0x05: 'ERROR_UNSUPPORTED_CMD',
}

PLDM_TYPES = {
    0x00: 'Base',
    0x01: 'SMBIOS',
    0x02: 'Platform',
    0x03: 'BIOS',
    0x04: 'FRU',
    0x05: 'FW Update',
    0x06: 'RDE',
    0x07: 'File Transfer',
    0x3F: 'OEM',
}

MCTP_TYPE_PLDM = 0x01
MCTP_TYPE_SPDM = 0x05
MCTP_TYPE_SECURED = 0x06

SPDM_CODES = {
    0x01: 'DIGESTS',
    0x02: 'CERTIFICATE',
    0x03: 'CHALLENGE_AUTH',
    0x04: 'VERSION',
    0x05: 'CHUNK_SEND_ACK',
    0x06: 'CHUNK_RESPONSE',
    0x60: 'MEASUREMENTS',
    0x61: 'CAPABILITIES',
    0x62: 'SUPPORTED_EVENT_TYPES',
    0x63: 'ALGORITHMS',
    0x64: 'KEY_EXCHANGE_RSP',
    0x65: 'FINISH_RSP',
    0x66: 'PSK_EXCHANGE_RSP',
    0x67: 'PSK_FINISH_RSP',
    0x68: 'HEARTBEAT_ACK',
    0x69: 'KEY_UPDATE_ACK',
    0x6A: 'ENCAPSULATED_REQUEST',
    0x6B: 'ENCAPSULATED_RESPONSE_ACK',
    0x6C: 'END_SESSION_ACK',
    0x6D: 'CSR',
    0x6E: 'SET_CERTIFICATE_RSP',
    0x6F: 'MEASUREMENT_EXTENSION_LOG',
    0x70: 'SUBSCRIBE_EVENT_TYPES_ACK',
    0x71: 'EVENT_ACK',
    0x7C: 'KEY_PAIR_INFO',
    0x7D: 'SET_KEY_PAIR_INFO_ACK',
    0x7E: 'VENDOR_DEFINED_RESPONSE',
    0x7F: 'ERROR',
    0x81: 'GET_DIGESTS',
    0x82: 'GET_CERTIFICATE',
    0x83: 'CHALLENGE',
    0x84: 'GET_VERSION',
    0x85: 'CHUNK_SEND',
    0x86: 'CHUNK_GET',
    0xE0: 'GET_MEASUREMENTS',
    0xE1: 'GET_CAPABILITIES',
    0xE2: 'GET_SUPPORTED_EVENT_TYPES',
    0xE3: 'NEGOTIATE_ALGORITHMS',
    0xE4: 'KEY_EXCHANGE',
    0xE5: 'FINISH',
    0xE6: 'PSK_EXCHANGE',
    0xE7: 'PSK_FINISH',
    0xE8: 'HEARTBEAT',
    0xE9: 'KEY_UPDATE',
    0xEA: 'GET_ENCAPSULATED_REQUEST',
    0xEB: 'DELIVER_ENCAPSULATED_RESPONSE',
    0xEC: 'END_SESSION',
    0xED: 'GET_CSR',
    0xEE: 'SET_CERTIFICATE',
    0xEF: 'GET_MEASUREMENT_EXTENSION_LOG',
    0xF0: 'SUBSCRIBE_EVENT_TYPES',
    0xF1: 'SEND_EVENT',
    0xFC: 'GET_KEY_PAIR_INFO',
    0xFD: 'SET_KEY_PAIR_INFO',
    0xFE: 'VENDOR_DEFINED_REQUEST',
    0xFF: 'RESPOND_IF_READY',
}

SPDM_ERROR_CODES = {
    0x01: 'InvalidRequest',
    0x02: 'InvalidSession',
    0x03: 'Busy',
    0x04: 'UnexpectedRequest',
    0x05: 'Unspecified',
    0x06: 'DecryptError',
    0x07: 'UnsupportedRequest',
    0x08: 'RequestInFlight',
    0x09: 'InvalidResponseCode',
    0x0A: 'SessionLimitExceeded',
    0x0B: 'SessionRequired',
    0x0C: 'ResetRequired',
    0x0D: 'ResponseTooLarge',
    0x0E: 'RequestTooLarge',
    0x0F: 'LargeResponse',
    0x10: 'MessageLost',
    0x11: 'InvalidPolicy',
    0x41: 'VersionMismatch',
    0x42: 'ResponseNotReady',
    0x43: 'RequestResynch',
    0x44: 'OperationFailed',
    0x45: 'NoPendingRequests',
    0xFF: 'VendorDefined',
}

# (name, bit, width). Two-bit fields decode to name=value.
CAPABILITY_FLAGS = (
    ('CACHE', 0, 1), ('CERT', 1, 1), ('CHAL', 2, 1), ('MEAS', 3, 2), ('MEAS_FRESH', 5, 1), ('ENCRYPT', 6, 1),
    ('MAC', 7, 1), ('MUT_AUTH', 8, 1), ('KEY_EX', 9, 1), ('PSK', 10, 2), ('ENCAP', 12, 1), ('HBEAT', 13, 1),
    ('KEY_UPD', 14, 1), ('HANDSHAKE_IN_CLEAR', 15, 1), ('PUB_KEY_ID', 16, 1), ('CHUNK', 17, 1),
    ('ALIAS_CERT', 18, 1), ('SET_CERT', 19, 1), ('CSR', 20, 1), ('CERT_INSTALL_RESET', 21, 1), ('EP_INFO', 22, 2),
    ('MEL', 24, 1), ('EVENT', 25, 1), ('MULTI_KEY', 26, 2), ('GET_KEY_PAIR_INFO', 28, 1),
    ('SET_KEY_PAIR_INFO', 29, 1),
)

# bit -> (name, size in bytes)
BASE_ASYM_ALGOS = {
    0: ('RSASSA_2048', 256), 1: ('RSAPSS_2048', 256), 2: ('RSASSA_3072', 384), 3: ('RSAPSS_3072', 384),
    4: ('ECDSA_P256', 64), 5: ('RSASSA_4096', 512), 6: ('RSAPSS_4096', 512), 7: ('ECDSA_P384', 96),
    8: ('ECDSA_P521', 132), 9: ('SM2_P256', 64), 10: ('EdDSA_25519', 64), 11: ('EdDSA_448', 114),
}
BASE_HASH_ALGOS = {
    0: ('SHA256', 32), 1: ('SHA384', 48), 2: ('SHA512', 64), 3: ('SHA3_256', 32), 4: ('SHA3_384', 48),
    5: ('SHA3_512', 64), 6: ('SM3_256', 32),
}
MEAS_HASH_ALGOS = {
    0: ('RawBitStream', 0), 1: ('SHA256', 32), 2: ('SHA384', 48), 3: ('SHA512', 64), 4: ('SHA3_256', 32),
    5: ('SHA3_384', 48), 6: ('SHA3_512', 64), 7: ('SM3_256', 32),
}
DHE_GROUPS = {
    0: ('ffdhe2048', 256), 1: ('ffdhe3072', 384), 2: ('ffdhe4096', 512), 3: ('secp256r1', 64),
    4: ('secp384r1', 96), 5: ('secp521r1', 132), 6: ('SM2_P256', 64),
}
AEAD_SUITES = {0: ('AES_128_GCM', 0), 1: ('AES_256_GCM', 0), 2: ('CHACHA20_POLY1305', 0), 3: ('SM4_GCM', 0)}
KEY_SCHEDULES = {0: ('SPDM', 0)}
ALG_STRUCT_TYPES = {
    2: ('DHE', DHE_GROUPS),
    3: ('AEAD', AEAD_SUITES),
    4: ('ReqBaseAsym', BASE_ASYM_ALGOS),
    5: ('KeySchedule', KEY_SCHEDULES),
}

MEASUREMENT_TYPES = {
    0x00: 'ImmutableROM',
    0x01: 'MutableFW',
    0x02: 'HWConfig',
    0x03: 'FWConfig',
    0x04: 'Manifest',
    0x05: 'DeviceMode',
    0x06: 'FWVersion',
    0x07: 'FWSecurityVersion',
    0x08: 'HashExtended',
    0x09: 'Informational',
    0x0A: 'StructuredManifest',
}

MEAS_SUMMARY_TYPES = {0x00: 'none', 0x01: 'TCB', 0xFF: 'all'}
KEY_UPDATE_OPS = {1: 'UpdateKey', 2: 'UpdateAllKeys', 3: 'VerifyNewKey'}


class Truncated(Exception):
    pass


class Reader:
    def __init__(self, data, pos=0):
        self.data = data
        self.pos = pos

    def take(self, n):
        if n < 0 or self.pos + n > len(self.data):
            raise Truncated()
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def uint(self, n):
        return int.from_bytes(self.take(n), 'little')

    def u8(self):
        return self.uint(1)

    def u16(self):
        return self.uint(2)

    def u32(self):
        return self.uint(4)

    def rest(self):
        return self.take(len(self.data) - self.pos)

    def remaining(self):
        return len(self.data) - self.pos


def short_hex(data, limit=8):
    text = ''.join('%02X' % b for b in data[:limit])
    return text + '..' if len(data) > limit else text


def code_name(code):
    return SPDM_CODES.get(code, 'CODE_0x%02X' % code)


def bit_names(value, table):
    return [table[bit][0] if bit in table else 'bit%d' % bit for bit in range(32) if value & (1 << bit)]


def first_size(value, table):
    """Size of the lowest selected algorithm, or None if nothing known is selected."""
    for bit in range(32):
        if value & (1 << bit) and bit in table:
            return table[bit][1]
    return None


def algo_text(value, table):
    names = bit_names(value, table)
    return '|'.join(names) if names else 'none'


def capability_text(flags):
    names = []
    for name, bit, width in CAPABILITY_FLAGS:
        field = (flags >> bit) & ((1 << width) - 1)
        if field:
            names.append(name if width == 1 else '%s=%d' % (name, field))
    return ' '.join(names) if names else 'none'


def version_text(byte):
    return '%d.%d' % (byte >> 4, byte & 0x0F)


def parse_der_certs(chain):
    """Count the DER certificates in a certificate chain body."""
    count, pos = 0, 0
    while pos + 2 <= len(chain) and chain[pos] == 0x30:
        length = chain[pos + 1]
        header = 2
        if length & 0x80:
            n = length & 0x7F
            if n == 0 or pos + 2 + n > len(chain):
                break
            length = int.from_bytes(chain[pos + 2:pos + 2 + n], 'big')
            header += n
        pos += header + length
        if pos > len(chain):
            break
        count += 1
    return count


PEC_PRESENT = 'Present (verify)'
PEC_ABSENT = 'Absent'
OTHER_HIDE = 'Hide'
OTHER_SHOW = 'Show as raw I3C transfers'
SPDM_ALL = 'SPDM and secured messages'
SPDM_ONLY = 'SPDM only'
SPDM_OFF = 'Off'
PLDM_ON = 'On'
PLDM_OFF = 'Off'


def crc8(data, crc=0):
    """SMBus / DSP0233 PEC: CRC-8, polynomial 0x07, initial value 0."""
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def to_int(value):
    if isinstance(value, (bytes, bytearray)):
        return value[0] if value else 0
    return int(value)


def hex_bytes(data):
    return ' '.join('%02X' % b for b in data)


def lookup(table, code):
    return table.get(code, '0x%02X' % code)


def decode_message(msg_type, body):
    """Return a short description of a reassembled message. `body` excludes the message type byte."""
    if msg_type == 0x00 and len(body) >= 2:
        rq = bool(body[0] & 0x80)
        datagram = bool(body[0] & 0x40)
        iid = body[0] & 0x1F
        cmd = lookup(CONTROL_COMMANDS, body[1])
        text = '%s %s iid=%d' % (cmd, 'Rq' if rq else 'Rsp', iid)
        if datagram:
            text += ' D'
        if not rq and len(body) >= 3:
            text += ' cc=%s' % lookup(CONTROL_COMPLETION_CODES, body[2])
        return text

    if msg_type == 0x01 and len(body) >= 3:
        rq = bool(body[0] & 0x80)
        iid = body[0] & 0x1F
        pldm_type = body[1] & 0x3F
        text = '%s %s %s iid=%d' % (lookup(PLDM_TYPES, pldm_type), pldm_command_name(pldm_type, body[2]),
                                    'Rq' if rq else 'Rsp', iid)
        if not rq and len(body) >= 4:
            text += ' cc=%s' % pldm_completion_name(pldm_type, body[3])
        return text

    if msg_type == 0x05 and len(body) >= 2:
        return 'v%d.%d %s' % (body[0] >> 4, body[0] & 0x0F, lookup(SPDM_CODES, body[1]))

    return ''


class Connection:
    """Negotiated SPDM state between one requester and responder."""

    def __init__(self):
        self.hash_size = None
        self.sig_size = None
        self.meas_hash_size = None
        self.dhe_size = None
        self.req_sig_size = None
        self.pending = None  # (code, param1, param2, fields, end_time) of the outstanding request
        self.cert = {}       # slot -> bytearray of the certificate chain read so far


class SpdmDecoder:
    """Decodes reassembled SPDM (MCTP type 0x05) and secured SPDM (type 0x06) messages.

    decode() returns (frame type, fields, summary parts), or None for other message types. Some payload fields are
    sized by the negotiated algorithms (hash, signature, DHE), so the ALGORITHMS selection is kept per connection.
    """

    def __init__(self, secured):
        self.secured = secured
        self.connections = {}  # (I3C address, EID pair) -> Connection
        self.sessions = {}     # session ID -> description

    def decode(self, message, address, src, dest, start_time, end_time):
        msg_type = message[0] & 0x7F
        if msg_type == MCTP_TYPE_SPDM:
            conn = self.connections.setdefault((address, min(src, dest), max(src, dest)), Connection())
            return self.decode_spdm(message[1:], conn, start_time, end_time)
        if msg_type == MCTP_TYPE_SECURED and self.secured:
            return self.decode_secured(message[1:])
        return None

    def decode_secured(self, body):
        fields = {'protocol': 'SPDM', 'raw': hex_bytes(body)}
        r = Reader(body)
        try:
            session_id = r.u32()
            seq = r.u16()
            length = r.u16()
        except Truncated:
            return 'secured', fields, ['Secured: truncated'], ['truncated']

        fields.update({'session_id': '0x%08X' % session_id, 'secured_seq': seq, 'length': length})
        parts = ['Secured session 0x%08X' % session_id, 'seq=%d' % seq, 'len=%d' % length]
        origin = self.sessions.get(session_id)
        if origin:
            parts.append('(%s)' % origin)
        errors = []
        if length != r.remaining():
            errors.append('length %d, %d bytes present' % (length, r.remaining()))
        return 'secured', fields, parts, errors

    def decode_spdm(self, body, conn, start_time, end_time):
        if len(body) < 4:
            return 'error', {'protocol': 'SPDM', 'raw': hex_bytes(body)}, ['SPDM: truncated header'], ['truncated']

        version, code, p1, p2 = body[0], body[1], body[2], body[3]
        is_request = bool(code & 0x80)
        name = code_name(code)
        fields = {
            'protocol': 'SPDM',
            'version': version_text(version),
            'code': '0x%02X' % code,
            'name': name,
            'param1': p1,
            'param2': p2,
            'raw': hex_bytes(body),
        }
        details = []
        errors = []

        pending = conn.pending
        if is_request:
            conn.pending = (code, p1, p2, fields, end_time)
        else:
            conn.pending = None
            if pending is not None:
                fields['request'] = code_name(pending[0])
                try:
                    fields['latency_ms'] = round(float(start_time - pending[4]) * 1000, 3)
                except (TypeError, ValueError):
                    pass
                expected = pending[0] & 0x7F
                if code not in (expected, 0x7F) and pending[0] != 0xFF:
                    errors.append('response to %s' % code_name(pending[0]))

        decoder = getattr(self, 'd_' + name.lower(), None)
        if decoder is not None:
            r = Reader(body, 4)
            try:
                decoder(r, version, p1, p2, conn, pending, fields, details)
            except Truncated:
                errors.append('truncated')

        parts = ['SPDM %s %s' % (fields['version'], name)] + details
        if 'latency_ms' in fields:
            parts.append('%.3f ms' % fields['latency_ms'])
        kind = 'error' if code == 0x7F or errors else ('request' if is_request else 'response')
        return kind, fields, parts, errors

    # Message decoders. Each reads the payload after the 4-byte header and adds `fields` and summary `details`.

    def d_version(self, r, version, p1, p2, conn, pending, fields, details):
        r.u8()
        count = r.u8()
        versions = []
        for _ in range(count):
            entry = r.u16()
            versions.append('%d.%d.%d' % (entry >> 12, (entry >> 8) & 0xF, (entry >> 4) & 0xF))
        fields['versions'] = ', '.join(versions)
        details.append('versions ' + fields['versions'])

    def d_get_capabilities(self, r, version, p1, p2, conn, pending, fields, details):
        if version >= 0x11:
            self.capabilities(r, version, fields, details)

    def d_capabilities(self, r, version, p1, p2, conn, pending, fields, details):
        self.capabilities(r, version, fields, details)

    def capabilities(self, r, version, fields, details):
        r.u8()
        ct_exponent = r.u8()
        r.take(2)
        flags = r.u32()
        fields['ct_exponent'] = ct_exponent
        fields['flags'] = '0x%08X' % flags
        fields['capabilities'] = capability_text(flags)
        details.append('CT=2^%d us' % ct_exponent)
        details.append(fields['capabilities'])
        if version >= 0x12 and r.remaining() >= 8:
            fields['data_transfer_size'] = r.u32()
            fields['max_spdm_msg_size'] = r.u32()
            details.append('xfer=%d max=%d' % (fields['data_transfer_size'], fields['max_spdm_msg_size']))

    def alg_structs(self, r, count, fields):
        texts = []
        selected = {}
        for _ in range(count):
            alg_type = r.u8()
            alg_count = r.u8()
            supported = r.uint(alg_count >> 4)
            r.take(4 * (alg_count & 0x0F))
            name, table = ALG_STRUCT_TYPES.get(alg_type, ('Type%d' % alg_type, {}))
            selected[alg_type] = supported
            fields[name.lower()] = algo_text(supported, table)
            texts.append('%s=%s' % (name, fields[name.lower()]))
        return texts, selected

    def d_negotiate_algorithms(self, r, version, p1, p2, conn, pending, fields, details):
        r.u16()
        r.u8()  # MeasurementSpecification
        r.u8()  # OtherParamsSupport
        base_asym = r.u32()
        base_hash = r.u32()
        r.take(12)
        ext_asym = r.u8()
        ext_hash = r.u8()
        r.take(2)
        r.take(4 * (ext_asym + ext_hash))
        fields['base_asym'] = algo_text(base_asym, BASE_ASYM_ALGOS)
        fields['base_hash'] = algo_text(base_hash, BASE_HASH_ALGOS)
        details.append('asym=%s hash=%s' % (fields['base_asym'], fields['base_hash']))
        texts, _ = self.alg_structs(r, p1, fields)
        details.extend(texts)

    def d_algorithms(self, r, version, p1, p2, conn, pending, fields, details):
        r.u16()
        r.u8()  # MeasurementSpecificationSel
        r.u8()  # OtherParamsSelection
        meas_hash = r.u32()
        base_asym = r.u32()
        base_hash = r.u32()
        r.take(12)
        ext_asym = r.u8()
        ext_hash = r.u8()
        r.take(2)
        r.take(4 * (ext_asym + ext_hash))
        fields['meas_hash'] = algo_text(meas_hash, MEAS_HASH_ALGOS)
        fields['base_asym'] = algo_text(base_asym, BASE_ASYM_ALGOS)
        fields['base_hash'] = algo_text(base_hash, BASE_HASH_ALGOS)
        details.append('asym=%s hash=%s meas=%s' % (fields['base_asym'], fields['base_hash'], fields['meas_hash']))

        conn.hash_size = first_size(base_hash, BASE_HASH_ALGOS)
        conn.sig_size = first_size(base_asym, BASE_ASYM_ALGOS)
        conn.meas_hash_size = first_size(meas_hash, MEAS_HASH_ALGOS)

        texts, selected = self.alg_structs(r, p1, fields)
        details.extend(texts)
        if 2 in selected:
            conn.dhe_size = first_size(selected[2], DHE_GROUPS)
        if 4 in selected:
            conn.req_sig_size = first_size(selected[4], BASE_ASYM_ALGOS)

    def d_digests(self, r, version, p1, p2, conn, pending, fields, details):
        slots = [slot for slot in range(8) if p2 & (1 << slot)]
        fields['slot_mask'] = '0x%02X' % p2
        details.append('slots ' + ','.join(str(s) for s in slots))
        if conn.hash_size and r.remaining() >= conn.hash_size * len(slots):
            for slot in slots:
                fields['digest_slot%d' % slot] = hex_bytes(r.take(conn.hash_size))

    def d_get_certificate(self, r, version, p1, p2, conn, pending, fields, details):
        slot = p1 & 0x0F
        offset = r.u16()
        length = r.u16()
        fields.update({'slot': slot, 'offset': offset, 'length': length})
        details.append('slot%d offset=%d length=%d' % (slot, offset, length))

    def d_certificate(self, r, version, p1, p2, conn, pending, fields, details):
        slot = p1 & 0x0F
        portion = r.u16()
        remainder = r.u16()
        chunk = r.take(portion)
        fields.update({'slot': slot, 'portion': portion, 'remainder': remainder})
        details.append('slot%d portion=%d remainder=%d' % (slot, portion, remainder))

        offset = pending[3].get('offset', 0) if pending and pending[0] == 0x82 else 0
        if offset == 0:
            conn.cert[slot] = bytearray()
        chain = conn.cert.setdefault(slot, bytearray())
        chain.extend(chunk)
        if remainder == 0:
            del conn.cert[slot]
            # Chain header: Length(2) Reserved(2) RootHash(H), then DER certificates.
            if len(chain) >= 4:
                total = int.from_bytes(chain[0:2], 'little')
                fields['chain_length'] = total
                text = 'chain %d bytes' % total
                if conn.hash_size and len(chain) >= 4 + conn.hash_size:
                    fields['root_hash'] = hex_bytes(chain[4:4 + conn.hash_size])
                    fields['cert_count'] = parse_der_certs(bytes(chain[4 + conn.hash_size:]))
                    text += ', %d certs' % fields['cert_count']
                details.append(text)

    def d_challenge(self, r, version, p1, p2, conn, pending, fields, details):
        fields['slot'] = p1
        fields['meas_summary'] = MEAS_SUMMARY_TYPES.get(p2, '0x%02X' % p2)
        nonce = r.take(32)
        fields['nonce'] = hex_bytes(nonce)
        details.append('slot%d meas=%s nonce=%s' % (p1, fields['meas_summary'], short_hex(nonce)))

    def d_challenge_auth(self, r, version, p1, p2, conn, pending, fields, details):
        fields['slot'] = p1 & 0x0F
        fields['slot_mask'] = '0x%02X' % p2
        details.append('slot%d' % fields['slot'])
        if not conn.hash_size:
            return
        fields['cert_chain_hash'] = hex_bytes(r.take(conn.hash_size))
        fields['nonce'] = hex_bytes(r.take(32))
        meas_requested = pending is not None and pending[0] == 0x83 and pending[2] != 0
        if meas_requested:
            fields['meas_summary_hash'] = hex_bytes(r.take(conn.hash_size))
        opaque = r.take(r.u16())
        fields['opaque_len'] = len(opaque)
        if version >= 0x13:
            r.take(8)
        fields['signature_len'] = r.remaining()
        details.append('sig=%dB' % r.remaining())

    def d_get_measurements(self, r, version, p1, p2, conn, pending, fields, details):
        signed = bool(p1 & 0x01)
        if p2 == 0x00:
            op = 'count'
        elif p2 == 0xFF:
            op = 'all'
        else:
            op = 'index %d' % p2
        fields['operation'] = op
        fields['signed'] = signed
        details.append(op + (' signed' if signed else ''))
        if signed:
            fields['nonce'] = hex_bytes(r.take(32))
            if version >= 0x11 and r.remaining():
                fields['slot'] = r.u8() & 0x0F

    def d_measurements(self, r, version, p1, p2, conn, pending, fields, details):
        block_count = r.u8()
        record = r.take(r.uint(3))
        fields['block_count'] = block_count
        request_op = pending[2] if pending and pending[0] == 0xE0 else None
        if request_op == 0x00:
            fields['total_indices'] = p1
            details.append('total=%d' % p1)

        blocks = []
        rr = Reader(record)
        while rr.remaining() >= 4:
            index = rr.u8()
            spec = rr.u8()
            measurement = rr.take(rr.u16())
            if spec & 0x01 and len(measurement) >= 3:
                value_type = measurement[0]
                value = measurement[3:3 + int.from_bytes(measurement[1:3], 'little')]
                type_name = MEASUREMENT_TYPES.get(value_type & 0x7F, 'Type0x%02X' % (value_type & 0x7F))
                if value_type & 0x80:
                    type_name += '(raw)'
                blocks.append('#%d %s %s' % (index, type_name, short_hex(value)))
                fields['meas_%d' % index] = '%s %s' % (type_name, hex_bytes(value))
            else:
                blocks.append('#%d spec=0x%02X %s' % (index, spec, short_hex(measurement)))
                fields['meas_%d' % index] = hex_bytes(measurement)
        if blocks:
            details.append('; '.join(blocks))
        elif request_op != 0x00:
            details.append('%d blocks' % block_count)

        fields['nonce'] = hex_bytes(r.take(32))
        opaque = r.take(r.u16())
        fields['opaque_len'] = len(opaque)
        if pending and pending[0] == 0xE0 and pending[1] & 0x01:
            if version >= 0x13:
                r.take(8)
            fields['signature_len'] = r.remaining()
            details.append('sig=%dB' % r.remaining())

    def d_key_exchange(self, r, version, p1, p2, conn, pending, fields, details):
        fields['meas_summary'] = MEAS_SUMMARY_TYPES.get(p1, '0x%02X' % p1)
        fields['slot'] = p2
        fields['req_session_id'] = '0x%04X' % r.u16()
        r.u8()  # SessionPolicy (1.2+), reserved before
        r.u8()
        fields['random'] = hex_bytes(r.take(32))
        details.append('slot%d ReqSessionID=%s' % (p2, fields['req_session_id']))
        if conn.dhe_size:
            fields['exchange_data'] = hex_bytes(r.take(conn.dhe_size))

    def d_key_exchange_rsp(self, r, version, p1, p2, conn, pending, fields, details):
        fields['heartbeat_period'] = p1
        rsp_session_id = r.u16()
        fields['rsp_session_id'] = '0x%04X' % rsp_session_id
        fields['mut_auth_requested'] = r.u8()
        fields['req_slot'] = r.u8()
        fields['random'] = hex_bytes(r.take(32))
        details.append('RspSessionID=%s' % fields['rsp_session_id'])
        self.record_session(pending, 0xE4, rsp_session_id, 'KEY_EXCHANGE', fields, details)

    def d_psk_exchange(self, r, version, p1, p2, conn, pending, fields, details):
        fields['meas_summary'] = MEAS_SUMMARY_TYPES.get(p1, '0x%02X' % p1)
        fields['req_session_id'] = '0x%04X' % r.u16()
        details.append('ReqSessionID=%s' % fields['req_session_id'])

    def d_psk_exchange_rsp(self, r, version, p1, p2, conn, pending, fields, details):
        rsp_session_id = r.u16()
        fields['rsp_session_id'] = '0x%04X' % rsp_session_id
        details.append('RspSessionID=%s' % fields['rsp_session_id'])
        self.record_session(pending, 0xE6, rsp_session_id, 'PSK_EXCHANGE', fields, details)

    def record_session(self, pending, request_code, rsp_session_id, origin, fields, details):
        if pending is None or pending[0] != request_code or 'req_session_id' not in pending[3]:
            return
        # libspdm / DSP0277: SessionID = RspSessionID << 16 | ReqSessionID
        session_id = (rsp_session_id << 16) | int(pending[3]['req_session_id'], 16)
        fields['session_id'] = '0x%08X' % session_id
        self.sessions[session_id] = origin
        details.append('session 0x%08X' % session_id)

    def d_finish(self, r, version, p1, p2, conn, pending, fields, details):
        fields['signature_included'] = bool(p1 & 0x01)
        fields['slot'] = p2
        if p1 & 0x01:
            details.append('signed slot%d' % p2)

    def d_key_update(self, r, version, p1, p2, conn, pending, fields, details):
        fields['operation'] = KEY_UPDATE_OPS.get(p1, '0x%02X' % p1)
        fields['key_update_tag'] = p2
        details.append('%s tag=%d' % (fields['operation'], p2))

    d_key_update_ack = d_key_update

    def d_end_session(self, r, version, p1, p2, conn, pending, fields, details):
        if p1 & 0x01:
            fields['preserve_state'] = True
            details.append('preserve negotiated state')

    def d_error(self, r, version, p1, p2, conn, pending, fields, details):
        fields['error_code'] = SPDM_ERROR_CODES.get(p1, '0x%02X' % p1)
        fields['error_data'] = p2
        details.append(fields['error_code'])
        if p1 == 0x42 and r.remaining() >= 4:
            rdt_exponent = r.u8()
            request_code = r.u8()
            token = r.u8()
            rdtm = r.u8()
            fields.update({'rdt_exponent': rdt_exponent, 'token': token, 'rdtm': rdtm,
                           'not_ready_request': code_name(request_code)})
            details.append('%s token=%d RDT=2^%d us x%d' % (code_name(request_code), token, rdt_exponent, rdtm))
        elif p2:
            details.append('data=0x%02X' % p2)

    def d_respond_if_ready(self, r, version, p1, p2, conn, pending, fields, details):
        fields['original_request'] = code_name(p1)
        fields['token'] = p2
        details.append('%s token=%d' % (code_name(p1), p2))

    def encapsulated(self, r, fields, details):
        if r.remaining() >= 2:
            inner = r.rest()
            fields['inner'] = code_name(inner[1])
            details.append('inner=%s' % fields['inner'])

    def d_encapsulated_request(self, r, version, p1, p2, conn, pending, fields, details):
        details.append('id=%d' % p1)
        self.encapsulated(r, fields, details)

    d_deliver_encapsulated_response = d_encapsulated_request

    def d_encapsulated_response_ack(self, r, version, p1, p2, conn, pending, fields, details):
        details.append('id=%d type=%d' % (p1, p2))
        if version >= 0x12:
            r.take(4)  # AckRequestID + reserved
        if p2 == 0x01:
            self.encapsulated(r, fields, details)

    def d_vendor_defined_request(self, r, version, p1, p2, conn, pending, fields, details):
        fields['standard_id'] = r.u16()
        fields['vendor_id'] = hex_bytes(r.take(r.u8()))
        payload = r.take(r.u16())
        fields['vendor_payload'] = hex_bytes(payload)
        details.append('std=%d vendor=%s len=%d' % (fields['standard_id'], fields['vendor_id'] or '-', len(payload)))

    d_vendor_defined_response = d_vendor_defined_request

    def d_chunk_send(self, r, version, p1, p2, conn, pending, fields, details):
        seq = r.u16()
        r.u16()
        size = r.u32()
        fields.update({'handle': p2, 'chunk_seq': seq, 'chunk_size': size, 'last_chunk': bool(p1 & 0x01)})
        if seq == 0:
            fields['large_message_size'] = r.u32()
        details.append('handle=%d seq=%d size=%d%s' % (p2, seq, size, ' last' if p1 & 0x01 else ''))

    d_chunk_response = d_chunk_send

    def d_chunk_send_ack(self, r, version, p1, p2, conn, pending, fields, details):
        seq = r.u16()
        fields.update({'handle': p2, 'chunk_seq': seq, 'early_error': bool(p1 & 0x01)})
        details.append('handle=%d seq=%d%s' % (p2, seq, ' early error' if p1 & 0x01 else ''))

    def d_chunk_get(self, r, version, p1, p2, conn, pending, fields, details):
        seq = r.u16()
        fields.update({'handle': p2, 'chunk_seq': seq})
        details.append('handle=%d seq=%d' % (p2, seq))


# PLDM (DSP0241 over MCTP, DSP0240 base) message header:
#   [0] Rq[7] | D[6] | rsvd[5] | instance ID[4:0]
#   [1] header version[7:6] (= 0) | PLDM type[5:0]
#   [2] command code
#   [3] completion code (responses only)
# All multi-byte fields are little endian.

PLDM_COMMANDS = {
    0x00: {  # Base, DSP0240
        0x01: 'SetTID', 0x02: 'GetTID', 0x03: 'GetPLDMVersion', 0x04: 'GetPLDMTypes', 0x05: 'GetPLDMCommands',
        0x06: 'SelectPLDMVersion', 0x07: 'NegotiateTransferParameters', 0x08: 'MultipartSend',
        0x09: 'MultipartReceive', 0x0A: 'GetMultipartTransferSupport',
    },
    0x02: {  # Platform Monitoring and Control, DSP0248
        0x01: 'SetTID', 0x02: 'GetTID', 0x03: 'GetTerminusUID', 0x04: 'SetEventReceiver', 0x05: 'GetEventReceiver',
        0x0A: 'PlatformEventMessage', 0x0B: 'PollForPlatformEventMessage', 0x0C: 'EventMessageSupported',
        0x0D: 'EventMessageBufferSize', 0x10: 'SetNumericSensorEnable', 0x11: 'GetSensorReading',
        0x12: 'GetSensorThresholds', 0x13: 'SetSensorThresholds', 0x14: 'RestoreSensorThresholds',
        0x15: 'GetSensorHysteresis', 0x16: 'SetSensorHysteresis', 0x17: 'InitNumericSensor',
        0x20: 'SetStateSensorEnables', 0x21: 'GetStateSensorReadings', 0x22: 'InitStateSensor',
        0x30: 'SetNumericEffecterEnable', 0x31: 'SetNumericEffecterValue', 0x32: 'GetNumericEffecterValue',
        0x38: 'SetStateEffecterEnables', 0x39: 'SetStateEffecterStates', 0x3A: 'GetStateEffecterStates',
        0x40: 'GetPLDMEventLogInfo', 0x41: 'EnablePLDMEventLogging', 0x42: 'ClearPLDMEventLog',
        0x43: 'GetPLDMEventLogTimestamp', 0x44: 'SetPLDMEventLogTimestamp', 0x45: 'ReadPLDMEventLog',
        0x46: 'GetPLDMEventLogPolicyInfo', 0x47: 'SetPLDMEventLogPolicy', 0x48: 'FindPLDMEventLogEntry',
        0x50: 'GetPDRRepositoryInfo', 0x51: 'GetPDR', 0x52: 'FindPDR', 0x53: 'GetPDRRepositorySignature',
        0x58: 'RunInitAgent',
    },
    0x03: {  # BIOS Control and Configuration, DSP0247
        0x01: 'GetBIOSTable', 0x02: 'SetBIOSTable', 0x03: 'UpdateBIOSTable', 0x04: 'GetBIOSTableTags',
        0x05: 'SetBIOSTableTags', 0x06: 'AcceptBIOSAttributesPendingValues',
        0x07: 'SetBIOSAttributeCurrentValue', 0x08: 'GetBIOSAttributeCurrentValueByHandle',
        0x09: 'GetBIOSAttributePendingValueByHandle', 0x0A: 'GetBIOSAttributeCurrentValueByType',
        0x0B: 'GetBIOSAttributePendingValueByType', 0x0C: 'GetDateTime', 0x0D: 'SetDateTime',
        0x0E: 'GetBIOSStringTableStringType', 0x0F: 'SetBIOSStringTableStringType',
    },
    0x04: {  # FRU Data, DSP0257
        0x01: 'GetFRURecordTableMetadata', 0x02: 'GetFRURecordTable', 0x03: 'SetFRURecordTable',
        0x04: 'GetFRURecordByOption',
    },
    0x05: {  # Firmware Update, DSP0267
        0x01: 'QueryDeviceIdentifiers', 0x02: 'GetFirmwareParameters', 0x03: 'QueryDownstreamDevices',
        0x04: 'QueryDownstreamIdentifiers', 0x05: 'GetDownstreamFirmwareParameters', 0x10: 'RequestUpdate',
        0x11: 'GetPackageData', 0x12: 'GetDeviceMetaData', 0x13: 'PassComponentTable', 0x14: 'UpdateComponent',
        0x15: 'RequestFirmwareData', 0x16: 'TransferComplete', 0x17: 'VerifyComplete', 0x18: 'ApplyComplete',
        0x19: 'GetMetaData', 0x1A: 'ActivateFirmware', 0x1B: 'GetStatus', 0x1C: 'CancelUpdateComponent',
        0x1D: 'CancelUpdate', 0x1E: 'ActivatePendingComponentImageSet', 0x1F: 'ActivatePendingComponentImage',
        0x20: 'RequestDownstreamDeviceUpdate',
    },
    0x06: {  # Redfish Device Enablement, DSP0218
        0x01: 'NegotiateRedfishParameters', 0x02: 'NegotiateMediumParameters', 0x03: 'GetSchemaDictionary',
        0x04: 'GetSchemaURI', 0x05: 'GetResourceETag', 0x06: 'GetOEMCount', 0x07: 'GetOEMName',
        0x08: 'GetRegistryCount', 0x09: 'GetRegistryDetails', 0x0A: 'SelectRegistryVersion',
        0x0B: 'GetMessageRegistry', 0x0C: 'GetSchemaFile', 0x10: 'RDEOperationInit',
        0x11: 'SupplyCustomRequestParameters', 0x12: 'RetrieveCustomResponseParameters',
        0x13: 'RDEOperationComplete', 0x14: 'RDEOperationStatus', 0x15: 'RDEOperationKill',
        0x16: 'RDEOperationEnumerate', 0x30: 'RDEMultipartSend', 0x31: 'RDEMultipartReceive',
    },
}

PLDM_COMPLETION_CODES = {
    0x00: 'SUCCESS',
    0x01: 'ERROR',
    0x02: 'ERROR_INVALID_DATA',
    0x03: 'ERROR_INVALID_LENGTH',
    0x04: 'ERROR_NOT_READY',
    0x05: 'ERROR_UNSUPPORTED_PLDM_CMD',
    0x20: 'ERROR_INVALID_PLDM_TYPE',
    0x21: 'INVALID_TRANSFER_CONTEXT',
    0x22: 'INVALID_DATA_TRANSFER_HANDLE',
    0x23: 'UNEXPECTED_TRANSFER_FLAG_OPERATION',
    0x24: 'INVALID_REQUESTED_SECTION_OFFSET',
}

# Command specific completion codes (0x80 and up) that are shared by a whole PLDM type.
PLDM_TYPE_COMPLETION_CODES = {
    0x05: {
        0x80: 'NOT_IN_UPDATE_MODE', 0x81: 'ALREADY_IN_UPDATE_MODE', 0x82: 'DATA_OUT_OF_RANGE',
        0x83: 'INVALID_TRANSFER_LENGTH', 0x84: 'INVALID_STATE_FOR_COMMAND', 0x85: 'INCOMPLETE_UPDATE',
        0x86: 'BUSY_IN_BACKGROUND', 0x87: 'CANCEL_PENDING', 0x88: 'COMMAND_NOT_EXPECTED',
        0x89: 'RETRY_REQUEST_FW_DATA', 0x8A: 'UNABLE_TO_INITIATE_UPDATE', 0x8B: 'ACTIVATION_NOT_REQUIRED',
        0x8C: 'SELF_CONTAINED_ACTIVATION_NOT_PERMITTED', 0x8D: 'NO_DEVICE_METADATA', 0x8E: 'RETRY_REQUEST_UPDATE',
        0x8F: 'NO_PACKAGE_DATA', 0x90: 'INVALID_TRANSFER_HANDLE', 0x91: 'INVALID_TRANSFER_OPERATION_FLAG',
        0x92: 'ACTIVATE_PENDING_IMAGE_NOT_PERMITTED', 0x93: 'PACKAGE_DATA_ERROR',
    },
}

TRANSFER_FLAGS = {0x01: 'Start', 0x02: 'Middle', 0x04: 'End', 0x05: 'StartAndEnd'}
TRANSFER_OP_FLAGS = {0x00: 'GetNextPart', 0x01: 'GetFirstPart'}

FW_DESCRIPTOR_TYPES = {
    0x0000: 'PCI Vendor ID', 0x0001: 'IANA Enterprise ID', 0x0002: 'UUID', 0x0003: 'PnP Vendor ID',
    0x0004: 'ACPI Vendor ID', 0x0005: 'IEEE Assigned Company ID', 0x0006: 'SCSI Vendor ID',
    0x0100: 'PCI Device ID', 0x0101: 'PCI Subsystem Vendor ID', 0x0102: 'PCI Subsystem ID',
    0x0103: 'PCI Revision ID', 0x0104: 'PnP Product Identifier', 0x0105: 'ACPI Product Identifier',
    0x0106: 'ASCII Model Number (Long)', 0x0107: 'ASCII Model Number (Short)', 0x0108: 'SCSI Product ID',
    0x0109: 'UBM Controller Device Code', 0xFFFF: 'Vendor Defined',
}
FW_STATES = {0: 'IDLE', 1: 'LEARN_COMPONENTS', 2: 'READY_XFER', 3: 'DOWNLOAD', 4: 'VERIFY', 5: 'APPLY',
             6: 'ACTIVATE'}
FW_TRANSFER_RESULTS = {0x00: 'success', 0x01: 'corrupt image', 0x02: 'version mismatch', 0x03: 'aborted',
                       0x09: 'timeout', 0x0A: 'generic error'}
FW_VERIFY_RESULTS = {0x00: 'success', 0x01: 'failure', 0x02: 'version mismatch', 0x03: 'security checks failed',
                     0x04: 'image incomplete', 0x09: 'timeout', 0x0A: 'generic error'}
FW_APPLY_RESULTS = {0x00: 'success', 0x01: 'success with activation method change', 0x02: 'memory write error',
                    0x09: 'timeout', 0x0A: 'generic error'}
FW_COMPONENT_RESPONSES = {
    0x00: 'can be updated', 0x01: 'identical stamp', 0x02: 'lower stamp', 0x03: 'invalid stamp',
    0x04: 'conflict', 0x05: 'prerequisites not met', 0x06: 'not supported', 0x07: 'security restrictions',
    0x08: 'incomplete component image set', 0x09: 'active image not updateable', 0x0A: 'version mismatch',
    0x0B: 'downgrade', 0x0C: 'already in progress',
}

PLATFORM_EVENT_CLASSES = {
    0x00: 'SensorEvent', 0x01: 'EffecterEvent', 0x02: 'RedfishTaskExecutedEvent', 0x03: 'RedfishMessageEvent',
    0x04: 'PldmPDRRepositoryChgEvent', 0x05: 'PldmMessagePollEvent', 0x06: 'HeartbeatTimerElapsedEvent',
}
PDR_TYPES = {
    1: 'Terminus Locator', 2: 'Numeric Sensor', 3: 'Numeric Sensor Initialization', 4: 'State Sensor',
    5: 'State Sensor Initialization', 6: 'Sensor Auxiliary Names', 7: 'OEM Unit', 8: 'OEM State Set',
    9: 'Numeric Effecter', 10: 'Numeric Effecter Initialization', 11: 'State Effecter',
    12: 'State Effecter Initialization', 13: 'Effecter Auxiliary Names', 14: 'Effecter OEM Semantic',
    15: 'Entity Association', 16: 'Entity Auxiliary Names', 17: 'OEM Entity ID', 18: 'Interrupt Association',
    19: 'PLDM Event Log', 20: 'FRU Record Set', 21: 'Compact Numeric Sensor', 126: 'OEM Device', 127: 'OEM',
}
SENSOR_OP_STATES = {0: 'enabled', 1: 'disabled', 2: 'unavailable', 3: 'status unknown', 4: 'failed',
                    5: 'initializing', 6: 'shutting down', 7: 'in test'}
# sensorDataSize / effecterDataSize -> (byte count, signed)
DATA_SIZES = {0: (1, False), 1: (1, True), 2: (2, False), 3: (2, True), 4: (4, False), 5: (4, True)}
BIOS_TABLE_TYPES = {0: 'String', 1: 'Attribute', 2: 'Attribute Value'}


def pldm_command_name(pldm_type, command):
    return PLDM_COMMANDS.get(pldm_type, {}).get(command, 'Cmd0x%02X' % command)


def pldm_completion_name(pldm_type, cc):
    name = PLDM_COMPLETION_CODES.get(cc) or PLDM_TYPE_COMPLETION_CODES.get(pldm_type, {}).get(cc)
    return name or '0x%02X' % cc


def ver32_text(value):
    """PLDM ver32: major.minor.update.alpha, each byte 0xFn (single digit) or BCD; 0xFF = not present."""
    def field(byte):
        return byte & 0x0F if byte >> 4 == 0x0F else (byte >> 4) * 10 + (byte & 0x0F)
    major, minor, update, alpha = (value >> 24) & 0xFF, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF
    text = '%d.%d' % (field(major), field(minor))
    if update != 0xFF:
        text += '.%d' % field(update)
    if alpha:
        text += chr(alpha) if 0x20 < alpha < 0x7F else '.%d' % alpha
    return text


def version_string(kind, data):
    """Firmware update version string, by its string type."""
    codec = {1: 'ascii', 2: 'utf-8', 3: 'utf-16', 4: 'utf-16-le', 5: 'utf-16-be'}.get(kind, 'latin-1')
    return bytes(data).decode(codec, 'replace').rstrip('\x00')


def bitmap_bits(data):
    return [i * 8 + bit for i, byte in enumerate(data) for bit in range(8) if byte & (1 << bit)]


def bcd(byte):
    return (byte >> 4) * 10 + (byte & 0x0F)


class PldmDecoder:
    """Decodes reassembled PLDM (MCTP type 0x01) messages.

    decode() returns (frame type, fields, summary parts, errors), like SpdmDecoder. Requests are paired with their
    responses by instance ID, PLDM type and command, per I3C address and EID pair.
    """

    def __init__(self):
        self.pending = {}  # (address, src, dest, iid, type, command) -> (request fields, end_time)

    def decode(self, message, address, src, dest, start_time, end_time):
        body = message[1:]
        if len(body) < 3:
            return 'error', {'protocol': 'PLDM', 'raw': hex_bytes(body)}, ['PLDM: truncated header'], ['truncated']

        rq, datagram, iid = bool(body[0] & 0x80), bool(body[0] & 0x40), body[0] & 0x1F
        hdr_ver, pldm_type, command = body[1] >> 6, body[1] & 0x3F, body[2]
        name = pldm_command_name(pldm_type, command)
        fields = {
            'protocol': 'PLDM',
            'pldm_type': lookup(PLDM_TYPES, pldm_type),
            'command': name,
            'command_code': '0x%02X' % command,
            'iid': iid,
            'raw': hex_bytes(body),
        }
        if datagram:
            fields['datagram'] = True
        details = []
        errors = []
        if hdr_ver != 0:
            errors.append('header version %d' % hdr_ver)

        role = 'Rq' if rq else 'Rsp'
        if datagram:
            role += ' D' if rq else ' (async)'
        parts = ['PLDM %s %s %s iid=%d' % (fields['pldm_type'], name, role, iid)]

        request = None
        if rq:
            if not datagram:
                self.pending[(address, src, dest, iid, pldm_type, command)] = (fields, end_time)
            r = Reader(body, 3)
        else:
            entry = self.pending.pop((address, dest, src, iid, pldm_type, command), None)
            if entry is not None:
                request = entry[0]
                try:
                    fields['latency_ms'] = round(float(start_time - entry[1]) * 1000, 3)
                except (TypeError, ValueError):
                    pass
            if len(body) < 4:
                errors.append('no completion code')
                return 'error', fields, parts, errors
            cc = body[3]
            fields['cc'] = pldm_completion_name(pldm_type, cc)
            parts.append('cc=%s' % fields['cc'])
            r = Reader(body, 4)

        # Error responses carry only the completion code.
        if rq or body[3] == 0x00:
            decoder = getattr(self, '%s_%s_%s' % ('rq' if rq else 'rsp', PLDM_TYPE_PREFIXES.get(pldm_type, '-'),
                                                  name.lower()), None)
            if decoder is not None:
                try:
                    decoder(r, request, fields, details)
                except Truncated:
                    errors.append('truncated')

        parts += details
        if 'latency_ms' in fields:
            parts.append('%.3f ms' % fields['latency_ms'])
        if errors or (not rq and body[3] != 0x00):
            kind = 'error'
        else:
            kind = 'request' if rq else 'response'
        return kind, fields, parts, errors

    # Message decoders, named <rq|rsp>_<type prefix>_<command name in lower case>. Each reads the payload after
    # the header (and completion code), and adds `fields` and summary `details`. `request` is the fields of the
    # matching request, or None.

    # Base (DSP0240)

    def rq_base_settid(self, r, request, fields, details):
        fields['tid'] = r.u8()
        details.append('TID=%d' % fields['tid'])

    rq_platform_settid = rq_base_settid

    def rsp_base_gettid(self, r, request, fields, details):
        fields['tid'] = r.u8()
        details.append('TID=%d' % fields['tid'])

    rsp_platform_gettid = rsp_base_gettid

    def rq_base_getpldmversion(self, r, request, fields, details):
        fields['transfer_handle'] = r.u32()
        fields['transfer_op'] = TRANSFER_OP_FLAGS.get(r.u8(), '?')
        fields['type_queried'] = lookup(PLDM_TYPES, r.u8())
        details.append('type=%s' % fields['type_queried'])

    def rsp_base_getpldmversion(self, r, request, fields, details):
        fields['next_transfer_handle'] = r.u32()
        flag = r.u8()
        fields['transfer_flag'] = TRANSFER_FLAGS.get(flag, '0x%02X' % flag)
        data = r.rest()
        if flag in (0x04, 0x05) and len(data) >= 4:
            fields['version_crc'] = '0x%08X' % int.from_bytes(data[-4:], 'little')
            data = data[:-4]
        versions = [ver32_text(int.from_bytes(data[i:i + 4], 'little')) for i in range(0, len(data) - 3, 4)]
        fields['versions'] = ', '.join(versions)
        if request:
            details.append('type=%s' % request.get('type_queried'))
        details.append('versions ' + (fields['versions'] or '-'))

    def rsp_base_getpldmtypes(self, r, request, fields, details):
        types = [lookup(PLDM_TYPES, t) for t in bitmap_bits(r.take(8))]
        fields['types'] = ', '.join(types)
        details.append('types ' + (fields['types'] or '-'))

    def rq_base_getpldmcommands(self, r, request, fields, details):
        pldm_type = r.u8()
        fields['type_queried'] = lookup(PLDM_TYPES, pldm_type)
        fields['type_queried_code'] = pldm_type
        fields['type_version'] = ver32_text(r.u32())
        details.append('type=%s v%s' % (fields['type_queried'], fields['type_version']))

    def rsp_base_getpldmcommands(self, r, request, fields, details):
        pldm_type = request.get('type_queried_code') if request else None
        commands = [pldm_command_name(pldm_type, c) for c in bitmap_bits(r.take(32))]
        fields['commands'] = ', '.join(commands)
        if request:
            details.append('type=%s' % request['type_queried'])
        details.append('%d commands' % len(commands))

    # Platform monitoring and control (DSP0248)

    def rq_platform_seteventreceiver(self, r, request, fields, details):
        fields['event_global_enable'] = r.u8()
        fields['transport_protocol'] = r.u8()
        fields['receiver_eid'] = r.u8()
        details.append('enable=%d receiver EID %d' % (fields['event_global_enable'], fields['receiver_eid']))
        if r.remaining() >= 2:
            fields['heartbeat_timer'] = r.u16()
            details.append('heartbeat=%ds' % fields['heartbeat_timer'])

    def rq_platform_platformeventmessage(self, r, request, fields, details):
        fields['format_version'] = r.u8()
        fields['tid'] = r.u8()
        event_class = r.u8()
        fields['event_class'] = PLATFORM_EVENT_CLASSES.get(event_class, '0x%02X' % event_class)
        data = r.rest()
        fields['event_data'] = hex_bytes(data)
        details.append('TID=%d %s' % (fields['tid'], fields['event_class']))
        if event_class == 0x00 and len(data) >= 2:
            details.append('sensor %d' % int.from_bytes(data[0:2], 'little'))

    def rsp_platform_platformeventmessage(self, r, request, fields, details):
        fields['event_status'] = r.u8()
        details.append('status=%d' % fields['event_status'])

    def rq_platform_getsensorreading(self, r, request, fields, details):
        fields['sensor_id'] = r.u16()
        fields['rearm'] = r.u8()
        details.append('sensor %d' % fields['sensor_id'])

    def rsp_platform_getsensorreading(self, r, request, fields, details):
        size = r.u8()
        op_state = r.u8()
        r.u8()  # sensorEventMessageEnable
        fields['present_state'] = r.u8()
        fields['previous_state'] = r.u8()
        fields['event_state'] = r.u8()
        fields['op_state'] = SENSOR_OP_STATES.get(op_state, '0x%02X' % op_state)
        if request:
            details.append('sensor %d' % request['sensor_id'])
        if size in DATA_SIZES:
            n, signed = DATA_SIZES[size]
            fields['reading'] = int.from_bytes(r.take(n), 'little', signed=signed)
            details.append('reading=%d' % fields['reading'])
        details.append(fields['op_state'])

    def rq_platform_getstatesensorreadings(self, r, request, fields, details):
        fields['sensor_id'] = r.u16()
        details.append('sensor %d' % fields['sensor_id'])

    def rsp_platform_getstatesensorreadings(self, r, request, fields, details):
        count = r.u8()
        states = []
        for i in range(count):
            op_state, present, previous, event = r.u8(), r.u8(), r.u8(), r.u8()
            fields['sensor_%d' % i] = '%s present=%d previous=%d event=%d' % (
                SENSOR_OP_STATES.get(op_state, '0x%02X' % op_state), present, previous, event)
            states.append(str(present))
        if request:
            details.append('sensor %d' % request['sensor_id'])
        details.append('present=' + ','.join(states))

    def rq_platform_setstateeffecterstates(self, r, request, fields, details):
        fields['effecter_id'] = r.u16()
        count = r.u8()
        states = []
        for _ in range(count):
            set_request, state = r.u8(), r.u8()
            states.append(str(state) if set_request else '-')
        fields['states'] = ','.join(states)
        details.append('effecter %d states=%s' % (fields['effecter_id'], fields['states']))

    def rq_platform_getstateeffecterstates(self, r, request, fields, details):
        fields['effecter_id'] = r.u16()
        details.append('effecter %d' % fields['effecter_id'])

    def rsp_platform_getstateeffecterstates(self, r, request, fields, details):
        count = r.u8()
        states = []
        for _ in range(count):
            r.u8()  # effecterOperationalState
            r.u8()  # pendingState
            states.append(str(r.u8()))
        fields['states'] = ','.join(states)
        if request:
            details.append('effecter %d' % request['effecter_id'])
        details.append('present=' + fields['states'])

    def rq_platform_setnumericeffectervalue(self, r, request, fields, details):
        fields['effecter_id'] = r.u16()
        size = r.u8()
        details.append('effecter %d' % fields['effecter_id'])
        if size in DATA_SIZES:
            n, signed = DATA_SIZES[size]
            fields['value'] = int.from_bytes(r.take(n), 'little', signed=signed)
            details.append('value=%d' % fields['value'])

    rq_platform_getnumericeffectervalue = rq_platform_getstateeffecterstates

    def rsp_platform_getnumericeffectervalue(self, r, request, fields, details):
        size = r.u8()
        r.u8()  # effecterOperationalState
        if request:
            details.append('effecter %d' % request['effecter_id'])
        if size in DATA_SIZES:
            n, signed = DATA_SIZES[size]
            fields['pending_value'] = int.from_bytes(r.take(n), 'little', signed=signed)
            fields['value'] = int.from_bytes(r.take(n), 'little', signed=signed)
            details.append('value=%d' % fields['value'])

    def rsp_platform_getpdrrepositoryinfo(self, r, request, fields, details):
        fields['repository_state'] = r.u8()
        r.take(26)  # update time, OEM update time
        fields['record_count'] = r.u32()
        fields['repository_size'] = r.u32()
        fields['largest_record_size'] = r.u32()
        details.append('%d records, %d bytes' % (fields['record_count'], fields['repository_size']))

    def rq_platform_getpdr(self, r, request, fields, details):
        fields['record_handle'] = r.u32()
        fields['transfer_handle'] = r.u32()
        fields['transfer_op'] = TRANSFER_OP_FLAGS.get(r.u8(), '?')
        fields['request_count'] = r.u16()
        details.append('record %d %s' % (fields['record_handle'], fields['transfer_op']))

    def rsp_platform_getpdr(self, r, request, fields, details):
        fields['next_record_handle'] = r.u32()
        fields['next_transfer_handle'] = r.u32()
        flag = r.u8()
        fields['transfer_flag'] = TRANSFER_FLAGS.get(flag, '0x%02X' % flag)
        count = r.u16()
        data = r.take(count)
        fields['record_data'] = hex_bytes(data)
        if request:
            details.append('record %d' % request['record_handle'])
        if flag in (0x01, 0x05) and len(data) >= 10:
            pdr_type = data[5]
            fields['pdr_type'] = PDR_TYPES.get(pdr_type, 'type %d' % pdr_type)
            details.append(fields['pdr_type'])
        details.append('%s %d bytes, next %d' % (fields['transfer_flag'], count, fields['next_record_handle']))

    # BIOS control and configuration (DSP0247)

    def rq_bios_getbiostable(self, r, request, fields, details):
        fields['transfer_handle'] = r.u32()
        fields['transfer_op'] = TRANSFER_OP_FLAGS.get(r.u8(), '?')
        table = r.u8()
        fields['table_type'] = BIOS_TABLE_TYPES.get(table, '0x%02X' % table)
        details.append('%s table %s' % (fields['table_type'], fields['transfer_op']))

    def rsp_bios_getbiostable(self, r, request, fields, details):
        fields['next_transfer_handle'] = r.u32()
        flag = r.u8()
        fields['transfer_flag'] = TRANSFER_FLAGS.get(flag, '0x%02X' % flag)
        data = r.rest()
        if request:
            details.append('%s table' % request['table_type'])
        details.append('%s %d bytes' % (fields['transfer_flag'], len(data)))

    def date_time(self, r, fields, details):
        second, minute, hour, day, month = (bcd(r.u8()) for _ in range(5))
        year = r.u16()
        fields['date_time'] = '%04d-%02d-%02d %02d:%02d:%02d' % (
            bcd(year >> 8) * 100 + bcd(year & 0xFF), month, day, hour, minute, second)
        details.append(fields['date_time'])

    def rsp_bios_getdatetime(self, r, request, fields, details):
        self.date_time(r, fields, details)

    def rq_bios_setdatetime(self, r, request, fields, details):
        self.date_time(r, fields, details)

    # FRU data (DSP0257)

    def rsp_fru_getfrurecordtablemetadata(self, r, request, fields, details):
        major, minor = r.u8(), r.u8()
        fields['fru_version'] = '%d.%d' % (major, minor)
        fields['table_max_size'] = r.u32()
        fields['table_length'] = r.u32()
        fields['record_set_count'] = r.u16()
        fields['record_count'] = r.u16()
        fields['table_checksum'] = '0x%08X' % r.u32()
        details.append('v%s length=%d records=%d' % (fields['fru_version'], fields['table_length'],
                                                    fields['record_count']))

    def rq_fru_getfrurecordtable(self, r, request, fields, details):
        fields['transfer_handle'] = r.u32()
        fields['transfer_op'] = TRANSFER_OP_FLAGS.get(r.u8(), '?')
        details.append(fields['transfer_op'])

    def rsp_fru_getfrurecordtable(self, r, request, fields, details):
        fields['next_transfer_handle'] = r.u32()
        flag = r.u8()
        fields['transfer_flag'] = TRANSFER_FLAGS.get(flag, '0x%02X' % flag)
        details.append('%s %d bytes' % (fields['transfer_flag'], r.remaining()))

    # Firmware update (DSP0267)

    def rsp_fwup_querydeviceidentifiers(self, r, request, fields, details):
        r.u32()  # DeviceIdentifiersLength
        count = r.u8()
        descriptors = []
        for i in range(count):
            kind = r.u16()
            data = r.take(r.u16())
            name = FW_DESCRIPTOR_TYPES.get(kind, '0x%04X' % kind)
            value = '0x' + data[::-1].hex().upper() if len(data) <= 4 else hex_bytes(data)
            fields['descriptor_%d' % i] = '%s %s' % (name, value)
            descriptors.append('%s=%s' % (name, value if len(data) <= 4 else short_hex(data)))
        details.append('; '.join(descriptors))

    def rsp_fwup_getfirmwareparameters(self, r, request, fields, details):
        fields['capabilities_during_update'] = '0x%08X' % r.u32()
        count = r.u16()
        active_type, active_len, pending_type, pending_len = r.u8(), r.u8(), r.u8(), r.u8()
        fields['active_version'] = version_string(active_type, r.take(active_len))
        fields['pending_version'] = version_string(pending_type, r.take(pending_len))
        fields['component_count'] = count
        details.append('active %s' % (fields['active_version'] or '-'))
        if fields['pending_version']:
            details.append('pending %s' % fields['pending_version'])
        components = []
        for i in range(count):
            r.u16()  # ComponentClassification
            identifier = r.u16()
            r.u8()   # ComponentClassificationIndex
            r.u32()  # ActiveComponentComparisonStamp
            a_type, a_len = r.u8(), r.u8()
            r.take(8)
            r.u32()  # PendingComponentComparisonStamp
            p_type, p_len = r.u8(), r.u8()
            r.take(8)
            r.u16()  # ComponentActivationMethods
            r.u32()  # CapabilitiesDuringUpdate
            active = version_string(a_type, r.take(a_len))
            pending = version_string(p_type, r.take(p_len))
            fields['component_%d' % i] = 'id 0x%04X active %s%s' % (
                identifier, active, ' pending %s' % pending if pending else '')
            components.append('0x%04X=%s' % (identifier, active))
        details.append('%d components' % count + (': ' + ', '.join(components) if components else ''))

    def rq_fwup_requestupdate(self, r, request, fields, details):
        fields['max_transfer_size'] = r.u32()
        fields['component_count'] = r.u16()
        fields['max_outstanding_requests'] = r.u8()
        fields['package_data_length'] = r.u16()
        kind, length = r.u8(), r.u8()
        fields['image_set_version'] = version_string(kind, r.take(length))
        details.append('%s components=%d max xfer=%d' % (fields['image_set_version'], fields['component_count'],
                                                         fields['max_transfer_size']))

    def rsp_fwup_requestupdate(self, r, request, fields, details):
        fields['fd_metadata_length'] = r.u16()
        fields['fd_will_get_package_data'] = r.u8()

    def component(self, r, fields):
        fields['component_classification'] = r.u16()
        fields['component_id'] = '0x%04X' % r.u16()
        fields['component_index'] = r.u8()
        fields['comparison_stamp'] = '0x%08X' % r.u32()

    def rq_fwup_passcomponenttable(self, r, request, fields, details):
        flag = r.u8()
        fields['transfer_flag'] = TRANSFER_FLAGS.get(flag, '0x%02X' % flag)
        self.component(r, fields)
        kind, length = r.u8(), r.u8()
        fields['component_version'] = version_string(kind, r.take(length))
        details.append('%s id %s %s' % (fields['transfer_flag'], fields['component_id'],
                                        fields['component_version']))

    def rsp_fwup_passcomponenttable(self, r, request, fields, details):
        response, code = r.u8(), r.u8()
        fields['component_response'] = response
        fields['component_response_code'] = FW_COMPONENT_RESPONSES.get(code, '0x%02X' % code)
        details.append(fields['component_response_code'])

    def rq_fwup_updatecomponent(self, r, request, fields, details):
        self.component(r, fields)
        fields['image_size'] = r.u32()
        fields['update_option_flags'] = '0x%08X' % r.u32()
        kind, length = r.u8(), r.u8()
        fields['component_version'] = version_string(kind, r.take(length))
        details.append('id %s %s size=%d' % (fields['component_id'], fields['component_version'],
                                             fields['image_size']))

    def rsp_fwup_updatecomponent(self, r, request, fields, details):
        response, code = r.u8(), r.u8()
        fields['compatibility_response'] = response
        fields['compatibility_response_code'] = FW_COMPONENT_RESPONSES.get(code, '0x%02X' % code)
        fields['update_option_flags_enabled'] = '0x%08X' % r.u32()
        fields['time_before_request_fw_data'] = r.u16()
        details.append(fields['compatibility_response_code'])

    def rq_fwup_requestfirmwaredata(self, r, request, fields, details):
        fields['offset'] = r.u32()
        fields['length'] = r.u32()
        details.append('offset=0x%X length=%d' % (fields['offset'], fields['length']))

    def rsp_fwup_requestfirmwaredata(self, r, request, fields, details):
        fields['data_length'] = r.remaining()
        if request:
            details.append('offset=0x%X' % request['offset'])
        details.append('%d bytes' % r.remaining())

    def rq_fwup_transfercomplete(self, r, request, fields, details):
        result = r.u8()
        fields['result'] = FW_TRANSFER_RESULTS.get(result, '0x%02X' % result)
        details.append(fields['result'])

    def rq_fwup_verifycomplete(self, r, request, fields, details):
        result = r.u8()
        fields['result'] = FW_VERIFY_RESULTS.get(result, '0x%02X' % result)
        details.append(fields['result'])

    def rq_fwup_applycomplete(self, r, request, fields, details):
        result = r.u8()
        fields['result'] = FW_APPLY_RESULTS.get(result, '0x%02X' % result)
        fields['activation_methods_modification'] = '0x%04X' % r.u16()
        details.append(fields['result'])

    def rq_fwup_activatefirmware(self, r, request, fields, details):
        fields['self_contained_activation'] = bool(r.u8())
        if fields['self_contained_activation']:
            details.append('self-contained')

    def rsp_fwup_activatefirmware(self, r, request, fields, details):
        fields['estimated_activation_time'] = r.u16()
        details.append('%ds' % fields['estimated_activation_time'])

    def rsp_fwup_getstatus(self, r, request, fields, details):
        current, previous = r.u8(), r.u8()
        fields['current_state'] = FW_STATES.get(current, '0x%02X' % current)
        fields['previous_state'] = FW_STATES.get(previous, '0x%02X' % previous)
        fields['aux_state'] = r.u8()
        fields['aux_state_status'] = r.u8()
        fields['progress_percent'] = r.u8()
        fields['reason_code'] = r.u8()
        fields['update_option_flags_enabled'] = '0x%08X' % r.u32()
        details.append('%s (was %s)' % (fields['current_state'], fields['previous_state']))
        if fields['progress_percent'] <= 100:
            details.append('%d%%' % fields['progress_percent'])

    def rsp_fwup_cancelupdate(self, r, request, fields, details):
        fields['non_functioning_components'] = bool(r.u8())
        fields['non_functioning_bitmap'] = '0x%016X' % r.uint(8)
        if fields['non_functioning_components']:
            details.append('non-functioning %s' % fields['non_functioning_bitmap'])


PLDM_TYPE_PREFIXES = {0x00: 'base', 0x02: 'platform', 0x03: 'bios', 0x04: 'fru', 0x05: 'fwup', 0x06: 'rde'}


class Transfer:
    """Bytes of one I3C private transfer, from the address header to the next START / Sr / STOP, or of one HDR-DDR
    Message, from the Command Word to its CRC Word."""

    def __init__(self, frame, after_start, ddr=False):
        self.address = to_int(frame.data['address'])
        self.read = bool(frame.data['read'])
        self.after_start = after_start
        self.start_time = frame.start_time
        self.end_time = frame.end_time
        self.data = []
        self.parity_errors = 0
        self.ddr = ddr
        self.ddr_command = to_int(frame.data['command']) if ddr else None
        self.ddr_errors = []

    def label(self):
        return '%s%s 0x%02X' % ('DDR ' if self.ddr else '', 'R' if self.read else 'W', self.address)


class Hla(HighLevelAnalyzer):
    pec_mode = ChoicesSetting(label='PEC', choices=(PEC_PRESENT, PEC_ABSENT))
    address_filter = StringSetting(label='Target address filter (hex, blank = all)')
    other_transfers = ChoicesSetting(label='Non-MCTP private transfers', choices=(OTHER_HIDE, OTHER_SHOW))
    spdm_mode = ChoicesSetting(label='SPDM decoding', choices=(SPDM_ALL, SPDM_ONLY, SPDM_OFF))
    pldm_mode = ChoicesSetting(label='PLDM decoding', choices=(PLDM_ON, PLDM_OFF))

    result_types = {
        'packet': {'format': '{{data.summary}}'},
        'ibi': {'format': '{{data.summary}}'},
        'i3c': {'format': '{{data.summary}}'},
        'request': {'format': '{{data.summary}}'},
        'response': {'format': '{{data.summary}}'},
        'error': {'format': '{{data.summary}}'},
        'secured': {'format': '{{data.summary}}'},
    }

    def __init__(self):
        self.pec_enabled = self.pec_mode != PEC_ABSENT
        self.show_other = self.other_transfers == OTHER_SHOW
        filt = (self.address_filter or '').strip()
        self.filter = int(filt, 16) if filt else None
        self.decoders = {}  # MCTP message type -> decoder
        if self.spdm_mode != SPDM_OFF:
            spdm = SpdmDecoder(self.spdm_mode == SPDM_ALL)
            self.decoders[MCTP_TYPE_SPDM] = self.decoders[MCTP_TYPE_SECURED] = spdm
        if self.pldm_mode != PLDM_OFF:
            self.decoders[MCTP_TYPE_PLDM] = PldmDecoder()

        self.transfer = None
        self.after_start = False  # the next address header follows a START, not an Sr
        self.direct_ccc = False   # inside a direct CCC: Sr + address transfers are CCC payloads
        self.messages = {}        # reassembly key -> {'seq', 'data', 'start_time'}

    def decode(self, frame):
        kind = frame.type

        if kind in ('start', 'restart', 'stop', 'hdr', 'hdr_exit', 'hdr_restart'):
            result = self.finish_transfer()
            self.after_start = kind == 'start'
            if kind == 'stop':
                self.direct_ccc = False
            return result

        if kind == 'address':
            result = self.finish_transfer()
            address = to_int(frame.data['address'])
            if address == I3C_BROADCAST_ADDRESS:
                self.direct_ccc = False
            elif frame.data.get('ack', True) and not self.direct_ccc:
                self.transfer = Transfer(frame, self.after_start)
            self.after_start = False
            return result

        if kind == 'ccc':
            self.direct_ccc = to_int(frame.data['data']) >= 0x80
            return None

        if kind.startswith('ddr_'):
            return self.decode_ddr(frame)

        if kind in ('write', 'read') and self.transfer is not None:
            if (kind == 'read') != self.transfer.read:
                return None
            self.transfer.data.append(to_int(frame.data['data']))
            self.transfer.end_time = frame.end_time
            if kind == 'write' and not frame.data.get('parity_ok', True):
                self.transfer.parity_errors += 1

        return None

    def decode_ddr(self, frame):
        kind = frame.type
        if kind == 'ddr_command':
            result = self.finish_transfer()
            read = bool(frame.data['read'])
            address = to_int(frame.data['address'])
            # CCC Indicator Words (write to 7'h7E) and Direct CCC Selector Words aren't private transfers.
            if not frame.data.get('ccc_selector') and not (address == I3C_BROADCAST_ADDRESS and not read):
                self.transfer = Transfer(frame, False, ddr=True)
                if not frame.data.get('parity_ok', True):
                    self.transfer.parity_errors += 1
            return result

        transfer = self.transfer
        if transfer is None or not transfer.ddr:
            return None
        transfer.end_time = frame.end_time

        if kind == 'ddr_data':
            word = to_int(frame.data['data'])
            transfer.data += [word >> 8, word & 0xFF]
            if not frame.data.get('parity_ok', True):
                transfer.parity_errors += 1
        elif kind == 'ddr_crc':
            if not frame.data.get('crc_ok', True):
                transfer.ddr_errors.append('CRC-5 0x%02X != 0x%02X' % (to_int(frame.data['crc']),
                                                                        to_int(frame.data['expected'])))
            return self.finish_transfer()
        elif kind == 'ddr_nack':
            self.transfer = None
        elif kind == 'ddr_end':
            transfer.ddr_errors.append('terminated by %s' % ('Controller' if transfer.read else 'Target'))
        elif kind == 'ddr_error':
            transfer.ddr_errors.append('DDR %s error' % frame.data.get('error', 'framing'))
        return None

    def finish_transfer(self):
        transfer, self.transfer = self.transfer, None
        if transfer is None:
            return None
        if self.filter is not None and transfer.address != self.filter:
            return None

        data = transfer.data
        if not data:
            # An IBI from a target without an IBI payload (or whose MDB the LLA lost) ends right after the ACK.
            if transfer.read and transfer.after_start:
                return AnalyzerFrame('ibi', transfer.start_time, transfer.end_time, {
                    'summary': 'IBI 0x%02X (no MDB)' % transfer.address,
                    'address': transfer.address,
                    'data': '',
                })
            return None
        if transfer.ddr:
            data = transfer.data = self.strip_ddr_padding(transfer)
        is_mctp = len(data) >= 4 + self.pec_enabled and data[0] == MCTP_HEADER_VERSION

        # A read straight after START is an IBI; MDB 0xAE announces a pending MCTP packet.
        if not is_mctp and transfer.read and transfer.after_start:
            if data[0] == MDB_PENDING_READ:
                summary = 'IBI 0x%02X: MCTP pending read' % transfer.address
            elif self.show_other:
                summary = 'IBI 0x%02X: MDB %s' % (transfer.address, hex_bytes(data))
            else:
                return None
            return AnalyzerFrame('ibi', transfer.start_time, transfer.end_time, {
                'summary': summary,
                'address': transfer.address,
                'mdb': data[0],
                'data': hex_bytes(data),
            })

        if not is_mctp:
            if not self.show_other:
                return None
            summary = '%s: %s' % (transfer.label(), hex_bytes(data))
            fields = {
                'address': transfer.address,
                'direction': 'read' if transfer.read else 'write',
                'data': hex_bytes(data),
            }
            if transfer.ddr:
                fields['ddr_command'] = transfer.ddr_command
                summary = '%s cmd=0x%02X: %s' % (transfer.label(), transfer.ddr_command, hex_bytes(data))
                if transfer.ddr_errors:
                    fields['error'] = '; '.join(transfer.ddr_errors)
                    summary += ' | ERR: ' + fields['error']
            fields['summary'] = summary
            return AnalyzerFrame('i3c', transfer.start_time, transfer.end_time, fields)

        return self.decode_packet(transfer)

    def strip_ddr_padding(self, transfer):
        """HDR-DDR carries whole 16-bit words, so an odd-length packet ends with a 0x00 pad byte. With a PEC the pad
        is recognised by the PEC matching one byte earlier. That is ambiguous with an even-length packet whose own
        PEC is 0x00 (data ending in its CRC-8 always has a CRC-8 of 0), but padding is far more likely (about 1 in 2
        packets vs 1 in 256). Without a PEC the pad can't be told apart and is kept."""
        data = transfer.data
        if not self.pec_enabled or len(data) < 3 or data[-1] != 0x00:
            return data
        if crc8([(transfer.address << 1) | transfer.read] + data[:-2]) == data[-2]:
            return data[:-1]
        return data

    def decode_packet(self, transfer):
        data = transfer.data
        errors = []
        fields = {
            'address': transfer.address,
            'direction': 'read' if transfer.read else 'write',
        }

        if self.pec_enabled:
            packet, pec = data[:-1], data[-1]
            expected = crc8([(transfer.address << 1) | transfer.read] + packet)
            fields['pec'] = pec
            fields['pec_ok'] = pec == expected
            if pec != expected:
                errors.append('PEC 0x%02X != 0x%02X' % (pec, expected))
        else:
            packet = data

        if transfer.parity_errors:
            errors.append('%d parity error(s)' % transfer.parity_errors)
        errors += transfer.ddr_errors
        if transfer.ddr:
            fields['mode'] = 'HDR-DDR'
            fields['ddr_command'] = transfer.ddr_command

        dest, src, flags = packet[1], packet[2], packet[3]
        som = bool(flags & 0x80)
        eom = bool(flags & 0x40)
        seq = (flags >> 4) & 0x3
        tag_owner = bool(flags & 0x08)
        tag = flags & 0x07
        payload = packet[4:]

        fields.update({
            'dest_eid': dest,
            'src_eid': src,
            'som': som,
            'eom': eom,
            'seq': seq,
            'to': tag_owner,
            'tag': tag,
            'payload': hex_bytes(payload),
        })

        flag_text = ' '.join(name for name, on in (('SOM', som), ('EOM', eom)) if on)
        parts = [
            transfer.label(),
            'EID %d->%d' % (src, dest),
            ('%s seq%d tag%d%s' % (flag_text, seq, tag, ' TO' if tag_owner else '')).strip(),
        ]

        # Reassembly. Null EIDs are legal during discovery, so the I3C address and direction are part of the key.
        key = (transfer.address, transfer.read, src, dest, tag_owner, tag)
        message = self.messages.get(key)
        if som:
            if message is not None:
                errors.append('previous message dropped (no EOM)')
            message = {'seq': seq, 'data': list(payload), 'start_time': transfer.start_time}
            self.messages[key] = message
        elif message is None:
            errors.append('no SOM')
        elif seq != (message['seq'] + 1) % 4:
            errors.append('seq %d, expected %d' % (seq, (message['seq'] + 1) % 4))
            del self.messages[key]
            message = None
        else:
            message['seq'] = seq
            message['data'].extend(payload)

        if som and payload:
            msg_type = payload[0] & 0x7F
            fields['msg_type'] = lookup(MESSAGE_TYPES, msg_type)
            fields['ic'] = bool(payload[0] & 0x80)
            parts.append(fields['msg_type'])
            if not eom and msg_type in self.decoders:
                if msg_type == MCTP_TYPE_SPDM and len(payload) >= 3:
                    parts.append(code_name(payload[2]))
                elif msg_type == MCTP_TYPE_PLDM and len(payload) >= 4:
                    parts.append(pldm_command_name(payload[2] & 0x3F, payload[3]))

        if eom and message is not None:
            del self.messages[key]
            body = message['data']
            decoder = self.decoders.get(body[0] & 0x7F) if body else None
            decoded = decoder and decoder.decode(bytes(body), transfer.address, src, dest,
                                                 message['start_time'], transfer.end_time)
            if decoded:
                return self.message_frame(transfer, fields, body, decoded, errors)
            fields['message'] = hex_bytes(body)
            fields['message_len'] = len(body)
            if body:
                msg_type = body[0] & 0x7F
                fields['msg_type'] = lookup(MESSAGE_TYPES, msg_type)
                detail = decode_message(msg_type, body[1:])
                if detail:
                    fields['detail'] = detail
                    if not som:
                        parts.append(fields['msg_type'])
                    parts.append(detail)
                if not som:
                    parts.append('(%d bytes)' % len(body))

        if self.pec_enabled and not errors:
            parts.append('PEC OK')
        if errors:
            fields['error'] = '; '.join(errors)
            parts.append('ERR: ' + fields['error'])

        fields['summary'] = ' | '.join(parts)
        return AnalyzerFrame('packet', transfer.start_time, transfer.end_time, fields)

    def message_frame(self, transfer, fields, body, decoded, packet_errors):
        kind, message_fields, details, errors = decoded
        fields['message'] = hex_bytes(body)
        fields['message_len'] = len(body)
        fields.update(message_fields)
        parts = [transfer.label(),
                 'EID %d->%d' % (fields['src_eid'], fields['dest_eid'])] + details
        if not fields['som']:
            parts.append('(%d bytes)' % len(body))
        errors = packet_errors + errors
        if self.pec_enabled and not packet_errors:
            parts.append('PEC OK')
        if errors:
            fields['error'] = '; '.join(errors)
            parts.append('ERR: ' + fields['error'])
            if kind != 'secured':
                kind = 'error'
        fields['summary'] = ' | '.join(parts)
        return AnalyzerFrame(kind, transfer.start_time, transfer.end_time, fields)
