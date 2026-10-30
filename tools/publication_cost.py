"""Decode DOMAIN_PUBLICATION_COST from a stopped guest, without guest decisions.

ABI v2: two 512-byte rows indexed by control CPU 1/2. Word 63 is
release-published original Job sequence. Flags: 1 frozen retention, 2 identity
conflict, 4 capacity/arithmetic overflow, 8 sample chronology failure.
Incomplete, conflicted or overflowed records are never accepted as evidence.
"""
import struct

SCHEMA=0x4359505542430002
BANK_BYTES=1024


def decode_publication_cost(raw, expected=None):
    """Return complete rows; optional {cpu: identity subset} binds stop evidence.

    Identity keys: cpu, boot, controller, job, target, generation, model,
    domain, kind, version (Registry version). All values are a checkpoint
    before diagnostic serialization; none claims the final charged outcome.
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
        # A later paid begin may freeze a checkpoint without stop facts, but
        # finish always freezes any checkpoint already reporting a stop.
        if (w[31] or w[32]) and not w[1]:
            raise ValueError('publication cost checkpoint stop missing frozen retention')
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
            'release':at(23),'checkpoint':at(25),'checkpoint_cumulative_ns':w[27],
            'checkpoint_cap_error':w[28],'checkpoint_result_version':w[29],'checkpoint_result_error':w[30],
            'checkpoint_registry_stopped':bool(w[31]),'checkpoint_local_stop':bool(w[32]),
            'frozen':bool(w[1]),'charged_stop_bound':False})
    if any(cpu not in (1,2) for cpu in expected):raise ValueError('invalid expected control CPU')
    return result


def bind_publication_stop(row, context):
    """Join only a complete original optimization-stop context (20 u64).

    The caller must obtain context from the original stopped header's valid
    seqlock/schema/present receipt. This function checks full Job/CPU identity
    and exact existing debit split. It never derives a physical timestamp.
    """
    if len(context)!=20 or any(not isinstance(v,int) or v<0 or v>2**64-1 for v in context):
        raise ValueError('publication stop malformed context')
    c=context
    if c[0] not in (1,2,3) or c[9] not in (0,1) or c[13] or c[14] or c[15]!=1 or c[8]>20:
        raise ValueError('publication stop incomplete/overflow/outcome')
    # accept holds the control gate throughout. A readonly path enters
    # neither Registry nor local_stop, so it cannot produce the original
    # !wasStopped -> stopped transition. Readonly checkpoints stay unbound.
    if c[9]:
        raise ValueError('publication stop readonly cannot cause original stop transition')
    if bool(c[0]&1)!=row['checkpoint_registry_stopped']:
        raise ValueError('publication stop Registry-stop disagrees with checkpoint')
    if row['checkpoint_local_stop'] and not c[0]&2:
        raise ValueError('publication stop checkpoint local stop disappeared')
    bindings={'cpu':18,'boot':2,'controller':3,'job':4,'target':5,'generation':6,'model':16}
    if any(row[k]!=c[i] for k,i in bindings.items()) or row['start']['wall_ns']!=c[1] or row['start']['cpu_ns']!=c[19]:
        raise ValueError('publication stop identity mismatch')
    if row['decode_ns']!=c[10] or c[10]+c[11]>2**64-1 or c[10]+c[11]!=c[12] or c[12]<row['checkpoint_cumulative_ns']:
        raise ValueError('publication stop charged cumulative mismatch')
    if row['registry_status'] in (2,3):
        if (c[7],c[8])!=(row['registry_version'],row['registry_error']):
            raise ValueError('publication stop changed original Registry receipt')
    elif c[7] or not c[8]:
        raise ValueError('publication stop malformed pre-Registry outcome')
    return {**row,'charged_stop_bound':True,'charged_cumulative_ns':c[12],
        'charged_publication_ns':c[11],'final_result_version':c[7],
        'final_result_error':c[8],'final_stop_flags':c[0]}
