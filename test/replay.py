# Replays a real capture through the MCTP over I3C HLA, with PLDM and SPDM decoding on.
# Usage: python3 test/replay.py <data_table.csv> <legacy_export_hex.txt>
#   data_table.csv: Logic 2 data table export of the MIPI I3C analyzer (types and timing)
#   legacy_export_hex.txt: legacy export of the same analyzer with hex radix (byte values)
import csv, importlib.util, os, re, sys
W = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, W + '/mctp-i3c-hla/test')
from saleae.analyzers import AnalyzerFrame

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path); m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m); return m

mctp = load('mctp', W + '/mctp-i3c-hla/HighLevelAnalyzer.py')

def frames(table, legacy):
    rows = list(csv.DictReader(open(table, encoding='utf-8', newline='')))
    events = [l.split(',', 1)[1].strip() for l in open(legacy).read().splitlines()[1:]]
    assert len(rows) == len(events), (len(rows), len(events))
    for r, ev in zip(rows, events):
        t0 = float(r['start_time']); t1 = t0 + float(r['duration'])
        hexes = [int(h, 16) for h in re.findall(r'0x([0-9A-F]{2})', ev)]
        d = {}
        if r['type'] == 'address':
            d = {'address': hexes[0], 'read': r['read'] == 'true', 'ack': r['ack'] == 'true'}
        elif r['type'] in ('write', 'ccc'):
            d = {'data': hexes[0], 'parity_ok': r['parity_ok'] != 'false'}
        elif r['type'] == 'read':
            d = {'data': hexes[0], 'more': r['more'] == 'true'}
        yield AnalyzerFrame(r['type'], t0, t1, d)

mctp.Hla.pec_mode = mctp.PEC_PRESENT; mctp.Hla.address_filter = ''; mctp.Hla.other_transfers = mctp.OTHER_SHOW
mctp.Hla.spdm_mode = mctp.SPDM_ALL; mctp.Hla.pldm_mode = mctp.PLDM_ON
m = mctp.Hla()
for f in frames(sys.argv[1], sys.argv[2]):
    p = m.decode(f)
    if p is not None:
        print('%.6f %-8s %s' % (p.start_time, p.type, p.data['summary']))
