"""Enforce the portable mechanism boundary from Cargo's resolved dependency graph."""
import json
import subprocess
try:from .doctor import ROOT,RUST_BIN,env
except ImportError:from doctor import ROOT,RUST_BIN,env

def validate_graph(metadata):
 names={p['id']:p['name'] for p in metadata['packages']}
 graph={n['id']:n['dependencies'] for n in metadata['resolve']['nodes']}
 for start in names:
  allowed_by_root={'cyxia-contracts':{'cyxia-contracts'},'cyxia-kernel-core':{'cyxia-contracts'},'cyxia-ai-runtime':{'cyxia-contracts','cyxia-kernel-core'},'cyxia-ai-fs':{'cyxia-contracts'},'cyxia-posix':{'cyxia-ai-fs','cyxia-contracts'}}
  if names[start] not in allowed_by_root:continue
  allowed=allowed_by_root[names[start]];seen={start};todo=list(graph[start])
  while todo:
   dep=todo.pop()
   if dep in seen:continue
   seen.add(dep)
   if names[dep] not in allowed:raise ValueError(names[start]+' depends on '+names[dep])
   todo.extend(graph[dep])
 return True

def check():
 p=subprocess.run([str(RUST_BIN/'cargo'),'metadata','--format-version','1'],cwd=ROOT,env=env(),capture_output=True,text=True,check=True,timeout=30)
 validate_graph(json.loads(p.stdout))
 # These crates intentionally forbid unsafe; this is enforced by rustc, not this string scanner.
 return {'portable_dependency_graph':'PASS'}
if __name__=='__main__':print(json.dumps(check()))
