"""Decode DOMAIN_PUBLICATION_COST from a stopped guest, without guest decisions.

ABI v1: two 512-byte rows indexed by control CPU 1/2. Word 63 is
release-published original Job sequence. Flags: 1 frozen stop, 2 identity
conflict, 4 capacity/arithmetic overflow, 8 sample chronology failure.
Incomplete, conflicted or overflowed records are never accepted as evidence.
"""
import struct

SCHEMA=0x4359505542430001
BANK_BYTES=1024


def decode_publication_cost(raw, expected=None):
    """Return complete rows; optional {cpu: identity subset} binds stop evidence.

    Identity keys: cpu, boot, controller, job, target, generation, model,
    domain, kind, version (Registry version). All costs use original physical
    samples; cumulative includes original same-Job retry debit and decode.
    """
    if len(raw)!=BANK_BYTES:
        raise ValueError('publication cost bank length')
    words=struct.unpack('<128Q',raw)
    result=[]
    expected={} if expected is None else expected
    for cpu in (1,2):
        w=words[(cpu-1)*64:cpu*64]
        if not any(w):
            if cpu in expected:raise ValueError('missing expected publication cost row')
            continue
        if w[0]!=SCHEMA or w[1] not in (0,1) or w[2]!=cpu:
            raise ValueError('publication cost schema/flags/CPU conflict')
        if not w[5] or w[63]!=w[5] or not all(w[i] for i in (3,4,7,8,9,10)):
            raise ValueError('publication cost incomplete/identity')
        if not (1<=w[9]<=16) or w[10] not in ((1,2) if w[9] in (1,16) else (1,)):
            raise ValueError('publication cost malformed family')
        # domains::Error ABI uses discriminants 0..19, recorded as code+1.
        if any(w[i]>20 for i in (22,28,30)):
            raise ValueError('publication cost malformed error code')
        if any(w[47:63]) or w[46] not in (0,1) or w[15]>5:
            raise ValueError('publication cost malformed/reserved/capacity')
        if w[20] not in (0,1,2,3) or w[31] not in (0,1) or w[32] not in (0,1):
            raise ValueError('publication cost malformed outcome')
        if bool(w[1])!=bool(w[31] or w[32]):
            raise ValueError('publication cost stop flags')
        n=w[15]
        # A protected new attempt always reads first+finished (at least two).
        # A cached receipt and an outer Registry error return before any read.
        if n==1 or (w[20] in (0,1) and n):
            raise ValueError('publication cost impossible Registry clock combination')
        if w[20]==3 and n not in (0,5):
            raise ValueError('publication cost impossible successful Registry stages')
        if w[20]==3 and n==5 and not w[46]:
            raise ValueError('publication cost missing successful native precommit')
        if any(w[33+n*2:43]):raise ValueError('publication cost stale Registry tail')
        samples=[(w[12],w[13])]+[(w[33+i*2],w[34+i*2]) for i in range(n)]
        if w[46]:
            if n!=5 or not (samples[4][0]<=w[16]<=samples[5][0] and samples[4][1]<=w[17]<=samples[5][1]):
                raise ValueError('publication cost precommit ordering')
        elif w[16] or w[17]:raise ValueError('publication cost malformed precommit')
        if w[20]:samples.append((w[18],w[19]))
        elif any(w[18:23]) or n or w[46]:raise ValueError('publication cost missing Registry return')
        samples.extend(((w[23],w[24]),(w[25],w[26])))
        if any(a[0]>b[0] or a[1]>b[1] for a,b in zip(samples,samples[1:])):
            raise ValueError('publication cost sample chronology')
        total=w[26]-w[13]+w[11]
        if total>2**64-1 or total!=w[27] or w[14]>total:
            raise ValueError('publication cost cumulative/overflow')
        if w[20] in (2,3):
            if tuple(w[43:46])!=tuple(w[3:6]):raise ValueError('publication cost Registry identity conflict')
            if w[20]==3 and (not w[21] or w[22] or w[29]!=w[21] or w[30]):
                raise ValueError('publication cost successful receipt changed')
            if w[20]==2 and (w[21] or not w[22] or w[29] or w[30]!=w[22]):
                raise ValueError('publication cost refused receipt changed')
        elif any(w[43:46]) or w[21]:raise ValueError('publication cost foreign receipt')
        if w[20]==1 and (not w[22] or w[29] or not w[30]):
            raise ValueError('publication cost malformed Registry error')
        if w[29] and w[30]:raise ValueError('publication cost ambiguous result')
        identity=dict(zip(('cpu','boot','controller','job','target','generation','model','domain','kind'),w[2:11]))
        identity['version']=w[21]
        for key,value in expected.get(cpu,{}).items():
            if key not in identity or identity[key]!=value:
                raise ValueError('publication cost expected identity mismatch: '+key)
        def at(i):return {'wall_ns':w[i],'cpu_ns':w[i+1]}
        result.append({**identity,'flags':w[1],'debit_ns':w[11],
            'start':at(12),'decode_ns':w[14],
            'registry_samples':[at(33+i*2) for i in range(n)],
            'precommit':at(16) if w[46] else None,
            'registry_return':at(18) if w[20] else None,
            'registry_status':w[20],'registry_version':w[21],'registry_error':w[22],
            'release':at(23),'final':at(25),'cumulative_ns':w[27],
            'cap_error':w[28],'result_version':w[29],'result_error':w[30],
            'registry_stopped':bool(w[31]),'local_stop':bool(w[32])})
    if any(cpu not in (1,2) for cpu in expected):raise ValueError('invalid expected control CPU')
    return result
