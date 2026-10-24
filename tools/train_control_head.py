#!/usr/bin/env python3
"""Reproducible synthetic-teacher distillation, NOT evidence of measured benefit.

Uses only Python's standard library. Frozen train/held-out seeds and generated
Q12 weights are recorded. Never downloads data, changes deployed models or runs
training on a business hot path. --check verifies checked-in artifact identity.
"""
import argparse, hashlib, json, math, random, struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SCHEMA=("CyxiaOS.core-head.experimental.v1;le64;input44;output24;monotonic-sample-window-start-end;exact-epochs-masks;"
        "features64-Q15:pressure,latency,benefit,business_pressure,reserved4,"
        "cpu8x(online,control,protected_control,protected_business,spare,efficiency,reserved);"
        "output:all-five-epochs-and-window,hold-grow-shrink-logits,desired-mask;no-implicit-authority\n")
def dataset(seed,n):
    rng=random.Random(seed); rows=[]
    for _ in range(n):
        p,l,g,b=[rng.random() for _ in range(4)]
        # Synthetic linear utility teacher. This is declared training data,
        # not real machine telemetry or a claim of performance improvement.
        scores=[0.0, 1.9*p+1.9*l+0.6*g-0.4*b-2.4, 1.0-1.8*p-1.8*l-0.2*g]
        rows.append(([1.,p,l,g,b],max(range(3),key=lambda i:scores[i])))
    return rows

def train():
    rows=dataset(20261024,1024); w=[[0.]*5 for _ in range(3)]
    for epoch in range(240):
        grad=[[0.]*5 for _ in range(3)]
        for x,y in rows:
            z=[sum(a*b for a,b in zip(v,x)) for v in w]; m=max(z)
            e=[math.exp(a-m) for a in z]; total=sum(e)
            for i in range(3):
                diff=e[i]/total-(i==y)
                for j in range(5): grad[i][j]+=diff*x[j]
        for i in range(3):
            for j in range(5): w[i][j]-=.65*(grad[i][j]/len(rows)+.0001*w[i][j])
    # Rank head: fit normalized spare/efficiency utility by batch regression.
    rng=random.Random(98513); rank_rows=[]
    for _ in range(512):
        x=[float(rng.randrange(2)) for _ in range(4)]+[rng.random(),rng.random(),0.]
        rank_rows.append((x, .75*x[4]+.25*x[5]))
    rank=[0.]*7
    for _ in range(300):
        g=[0.]*7
        for x,y in rank_rows:
            d=sum(a*b for a,b in zip(rank,x))-y
            for i in range(7): g[i]+=d*x[i]
        rank=[a-.2*b/len(rank_rows) for a,b in zip(rank,g)]
    # Rescale class logits uniformly to avoid saturation changing argmax.
    quant=[round(v*.22*4096) for row in w for v in row]+[round(v*4096) for v in rank]
    payload=b'CYXMDL01'+struct.pack('<22h',*quant)
    def infer(x):
        f=[32767]+[round(v*32767) for v in x[1:]]
        scores=[max(-32768,min(32767,int(sum(a*b for a,b in zip(quant[i*5:i*5+5],f))/4096))) for i in range(3)]
        return max(range(3),key=lambda i:scores[i])
    held=dataset(20261025,512)
    report={'format':'CYXMDL01','model_kind':'trained linear classifier and placement head',
        'training_data':'synthetic utility teacher, not observed hardware outcomes',
        'seed':20261024,'heldout_seed':20261025,'training_rows':1024,'heldout_rows':512,
        'epochs':240,'heldout_correct':sum(infer(x)==y for x,y in held),
        'weights_q12':quant,'model_sha256':hashlib.sha256(payload).hexdigest(),
        'schema_sha256':hashlib.sha256(SCHEMA.encode()).hexdigest(),
        'performance_benefit_verified':False,'full_16_domain_model':False}
    def words(d):return str(list(struct.unpack('<4Q',d)))+'\n'
    return {'core-head.bin':payload,'schema.txt':SCHEMA.encode(),
        'training.json':(json.dumps(report,indent=2)+'\n').encode(),
        'model-sha256.rs':words(hashlib.sha256(payload).digest()).encode(),
        'schema-sha256.rs':words(hashlib.sha256(SCHEMA.encode()).digest()).encode()}

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--check',action='store_true'); args=p.parse_args()
    output=ROOT/'ports/control-service'; output.mkdir(exist_ok=True)
    for name,content in train().items():
        path=output/name
        if args.check:
            if path.read_bytes()!=content:raise SystemExit('artifact differs: '+name)
        else:path.write_bytes(content)
    print('model artifacts match' if args.check else 'model artifacts generated')
if __name__=='__main__':main()
