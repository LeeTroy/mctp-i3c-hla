# MCTP over I3C — Saleae Logic 2 High Level Analyzer

Decodes DMTF **MCTP over I3C** (DSP0233) traffic and, optionally, **PLDM** (DSP0240 / DSP0241), **SPDM** (DSP0274) and **secured SPDM** (DSP0277 / DSP0275) messages carried over it. It runs on top of the [MIPI I3C low level analyzer](../mipi-i3c-lla).

Logic 2 only lets an HLA take a low level analyzer as its input, so SPDM can't be a separate HLA stacked on this one. The SPDM decoder from [spdm-mctp-hla](../spdm-mctp-hla) is built in here instead and is turned on with the **SPDM decoding** setting.

## Features

- Decodes MCTP packets carried in I3C private writes (controller → target) and private reads (target → controller)
- Transport header: header version, source and destination EID, SOM/EOM, packet sequence, TO, message tag
- PEC check: CRC-8 (poly 0x07) over `(addr << 1 | RnW)` plus all packet bytes. It can be turned off for links without a PEC.
- Reassembles multi-packet messages per (I3C address, direction, src EID, dst EID, TO, tag). Flags a missing SOM, a sequence gap, or a dropped message.
- Message types: Control, PLDM, NC-SI, Ethernet, NVMe-MI, SPDM, Secured, CXL, vendor defined
- Message detail for MCTP Control (command, Rq/Rsp, instance ID, completion code), PLDM (type, command, completion code) and SPDM (version, request/response code)
- IBI with MDB `0xAE` (MCTP pending read) shown as an `ibi` frame
- Broadcast and direct CCC traffic and NACKed headers are ignored. Optionally, non-MCTP private transfers are shown raw.
- HDR-DDR: MCTP packets in the Data Words of DDR Write / Read Commands are decoded like SDR transfers. The summary starts with `DDR W` / `DDR R`, and the frame gets `mode` = `HDR-DDR` and `ddr_command`. LLA CRC-5 and parity errors, early termination and framing errors show up in `error`. NACKed Commands, CCC Indicator Words and Direct CCC Selector Words are ignored.

### PLDM decoding

When it's on, the frame of the EOM packet of each PLDM message becomes a `request` / `response` / `error` frame. As with SPDM, the earlier packets of a multi-packet message stay `packet` frames, and the SOM packet shows the command name.

- Header: Rq / datagram bits, instance ID, PLDM type, command name, completion code (generic codes plus the FW Update specific `0x80`+ codes)
- Request/response pairing by instance ID, type and command, per I3C address and EID pair: response latency (`latency_ms`). This works in both directions, so FD → UA requests during a firmware update are paired too.
- Command names for Base, Platform (DSP0248), BIOS (DSP0247), FRU (DSP0257), FW Update (DSP0267) and RDE (DSP0218)
- Payload decode:
  - **Base**: SetTID / GetTID, GetPLDMVersion (ver32 versions, CRC), GetPLDMTypes, GetPLDMCommands (named commands)
  - **Platform**: SetEventReceiver, PlatformEventMessage (TID, event class, sensor ID), GetSensorReading (signed/unsigned reading, operational state), GetStateSensorReadings, Set/GetStateEffecterStates, Set/GetNumericEffecterValue, GetPDRRepositoryInfo, GetPDR (transfer flag, PDR type of the first part)
  - **BIOS**: GetBIOSTable, GetDateTime / SetDateTime
  - **FRU**: GetFRURecordTableMetadata, GetFRURecordTable
  - **FW Update**: QueryDeviceIdentifiers (named descriptors), GetFirmwareParameters (active/pending image set and per-component versions), RequestUpdate, PassComponentTable, UpdateComponent (component response codes), RequestFirmwareData (offset/length), TransferComplete / VerifyComplete / ApplyComplete results, ActivateFirmware, GetStatus (state, previous state, progress), CancelUpdate
  - Other commands show the header only. An error response (completion code ≠ SUCCESS) is decoded only up to the completion code.

### SPDM decoding

When it's on, the frame of the EOM packet of each SPDM message becomes a `request` / `response` / `error` / `secured` frame with the full SPDM decode. Logic 2 HLA frames can't overlap, so there is no frame spanning SOM to EOM. In a multi-packet message the earlier packets stay `packet` frames, and the SOM packet shows the SPDM code name.

- Header: SPDM version, request/response code name, Param1/Param2
- Request/response pairing per connection: response latency (`latency_ms`, from the end of the request to the SOM of the response) and a flag when a response doesn't match the outstanding request
- Tracks the negotiated algorithms (hash, signature, measurement hash, DHE group) from ALGORITHMS. These set the sizes of digests, nonces, exchange data and signatures in later messages.
- Payload decode:
  - **VERSION**: supported version list
  - **GET_CAPABILITIES / CAPABILITIES**: CT exponent, named capability flags, DataTransferSize / MaxSPDMmsgSize (1.2+)
  - **NEGOTIATE_ALGORITHMS / ALGORITHMS**: base asym/hash, measurement hash, DHE, AEAD, ReqBaseAsym, KeySchedule
  - **DIGESTS**: slot mask and per-slot digests
  - **GET_CERTIFICATE / CERTIFICATE**: slot, offset/length, portion/remainder. The chain is reassembled across reads, and the summary shows its length, root hash and DER certificate count.
  - **CHALLENGE / CHALLENGE_AUTH**: slot, measurement summary type, nonce, cert chain hash, signature length
  - **GET_MEASUREMENTS / MEASUREMENTS**: operation (count / all / index), signature request, and the measurement blocks (index, DMTF value type, value)
  - **KEY_EXCHANGE / KEY_EXCHANGE_RSP**, **PSK_EXCHANGE / _RSP**: Req/Rsp session IDs and the combined session ID
  - **FINISH, KEY_UPDATE, END_SESSION, HEARTBEAT, RESPOND_IF_READY, encapsulated flows, CHUNK_*, VENDOR_DEFINED_***
  - **ERROR**: named error code, with ResponseNotReady extended data (RDT, token, original request)
- Secured messages (MCTP type 0x06): session ID, sequence number and length, linked to the KEY_EXCHANGE / PSK_EXCHANGE that created the session. The payload is encrypted and isn't decoded.

## Frames

| Type | When | Main fields |
|------|------|-------------|
| `packet` | one per MCTP packet | `address`, `direction`, `dest_eid`, `src_eid`, `som`, `eom`, `seq`, `to`, `tag`, `msg_type`, `ic`, `payload`, `pec`, `pec_ok`, `error` |
| | on EOM | `message` (reassembled, starts with the message type byte), `message_len`, `detail` |
| `ibi` | IBI after START | `address`, `mdb`, `data` |
| `i3c` | non-MCTP private transfer (only if enabled) | `address`, `direction`, `data` |
| `request` / `response` | EOM packet of a PLDM message (PLDM decoding on) | all `packet` fields, `message`, plus `protocol` (`PLDM`), `pldm_type`, `command`, `command_code`, `iid`, `datagram`, `cc`, `raw`, `latency_ms` and command-specific fields |
| `request` / `response` | EOM packet of an SPDM message (SPDM decoding on) | all `packet` fields, `message`, plus `protocol` (`SPDM`), `version`, `code`, `name`, `param1`, `param2`, `raw`, `request`, `latency_ms` and message-specific fields |
| `error` | as above, for a PLDM completion code other than SUCCESS, an SPDM `ERROR`, a mismatched SPDM response, a truncated or malformed message, or a packet error (PEC, parity) | as above, plus `error` |
| `secured` | EOM packet of a secured SPDM message (only with `SPDM and secured messages`) | all `packet` fields, `session_id`, `secured_seq`, `length`, `raw` |

## Settings

- **PEC**: `Present (verify)` (default) or `Absent`
- **Target address filter**: a 7-bit dynamic address in hex, e.g. `0x09`. Leave blank to decode all targets.
- **Non-MCTP private transfers**: hide or show them raw
- **PLDM decoding**: `On` (default) or `Off` (plain MCTP packets with the short `detail` text)
- **SPDM decoding**: `SPDM and secured messages` (default), `SPDM only` (secured messages stay `packet` frames), or `Off` (plain MCTP packets with the short `detail` text)

## Usage

1. Load the I3C LLA (`CustomLLA/libmipi_i3c_analyzer.so`) and add **MIPI I3C** on SCL/SDA.
2. In the Extensions panel choose **⋮ → Load Existing Extension…** and pick `mctp-i3c-hla/extension.json`.
3. Add the **MCTP over I3C** analyzer and select the MIPI I3C analyzer as its input.

## Limitations

- HDR-DDR: DSP0233 (1.0.0 and 1.0.1) only defines MCTP over SDR. For DDR the analyzer assumes:
  - the same packet format and PEC (over `(addr << 1 | RnW)` plus the packet), with the first packet byte in bits 15:8 of the first Data Word;
  - any DDR Command Code (shown as `ddr_command`);
  - an odd-length packet padded with one `0x00` byte, as I3C does elsewhere.

  With a PEC, a trailing `0x00` is taken as the pad when the PEC matches the byte before it. This can't be told apart from an even-length packet whose own PEC is `0x00` (about 1 in 256 packets), so that case is decoded as padded. Without a PEC the pad byte is kept in the payload. If your devices use a different DDR mapping, `decode_ddr` and `strip_ddr_padding` in `HighLevelAnalyzer.py` are the places to change.
- The IC-bit message integrity check (CRC-32) is reported but not verified.
- PLDM: multipart transfers (GetPDR, GetBIOSTable, GetFRURecordTable, MultipartSend/Receive) are labelled per part but not reassembled. PDR, BIOS table and FRU record contents aren't parsed. RDE and File Transfer commands are named but not decoded.
- SPDM: only the lowest selected algorithm bit sizes fields (ALGORITHMS selects exactly one, so this holds for compliant traffic). Extended (ext asym / ext hash) algorithms aren't sized. CHUNK_SEND / CHUNK_RESPONSE chunks aren't reassembled. Secured message sequence numbers are assumed to be 2 bytes (the MCTP binding used by libspdm).
- A read right after START is treated as an IBI unless its first byte is a valid MCTP header (`0x01`). An IBI with no data byte is shown as `IBI 0xNN (no MDB)`.

## Tests

```bash
python3 test/test_hla.py    # MCTP transport
python3 test/test_pldm.py   # PLDM decoding, end to end from I3C frames
python3 test/test_spdm.py   # SPDM decoding, end to end from I3C frames
```

`test/saleae/` is a minimal stub of the Logic 2 `saleae.analyzers` module. The tests replay LLA frame sequences.

`test/replay.py <table.csv> <legacy_hex.txt>` replays a real capture through this HLA with PLDM and SPDM decoding on. Its inputs are a Logic 2 data table export of the MIPI I3C analyzer and a legacy hex export of the same analyzer.
