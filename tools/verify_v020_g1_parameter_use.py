#!/usr/bin/env python3
"""Verify checked G1 bindings and inventory remaining source candidates."""

import argparse
import ast
from collections import defaultdict
from hashlib import sha256
import json
import re
import subprocess

if __package__:
    from .verify_v020_g0_freeze import BASELINE, ROOT, registry_owners, require, strict_json
else:
    from verify_v020_g0_freeze import BASELINE, ROOT, registry_owners, require, strict_json


REGISTRY = "docs/design/v0.20-g1-parameter-bindings.json"
DECLARATION = re.compile(
    r"(?m)^[ \t]*(?:pub(?:\([^\n]+\))?[ \t]+)?const[ \t]+([A-Z_][A-Z_0-9]*)[ \t]*:"
)
RUST_TEST = re.compile(r"#\s*\[test\]\s*(?:#\[[^\n]*\]\s*)*fn\s+(\w+)\s*\(")
RUST_NONCODE = re.compile(
    r'''//[^\n]*|/\*|(?<!\w)(?:br|cr|r)(?P<hashes>\#{0,255})"|'''
    r'''(?:b|c)?"(?:\\.|[^"\\])*"|(?:b)?'(?:\\(?:u\{[0-9A-Fa-f_]+\}|x[0-9A-Fa-f]{2}|.)|[^'\\\n])' ''',
    re.S | re.X,
)
BLOCK_MARKER = re.compile(r"/\*|\*/")
CFG = re.compile(r"#\!?\[\s*cfg(?:_attr)?\s*\(")
GENERATED = re.compile(r"\binclude(?:_bytes|_str)?!\s*\(")
NUMBER = re.compile(
    r"(?<![\w'])0(?:[xX][\da-fA-F_]+|[bB][01_]+|[oO][0-7_]+)(?:[iu](?:size|\d+))?\b|"
    r"(?<![\w'])\d[\d_]*(?:\.(?!\.)\d[\d_]*)?(?:[eE][+-]?\d[\d_]*)?(?:[fiu](?:size|\d+))?\b"
)
DELIMITER = re.compile(r"[()\[\]{}=;]")
NATIVE_SUFFIXES = (".S", ".s", ".asm", ".ld", ".lds", ".x")


def mask_rust(source):
    """Mask comments in the first view and comments and literals in the second."""
    uncommented = list(source)
    code = list(source)
    offset = 0
    while match := RUST_NONCODE.search(source, offset):
        first, end = match.span()
        comment = match[0].startswith(("//", "/*"))
        if match[0] == "/*":
            depth = 1
            for token in BLOCK_MARKER.finditer(source, end):
                depth += 1 if token[0] == "/*" else -1
                if depth == 0:
                    end = token.end()
                    break
            require(depth == 0, "unterminated Rust block comment")
        elif match["hashes"] is not None:
            terminator = '"' + match["hashes"]
            last = source.find(terminator, end)
            require(last >= 0, "unterminated Rust raw string")
            end = last + len(terminator)
        blank = [char if char == "\n" else " " for char in source[first:end]]
        code[first:end] = blank
        if comment:
            uncommented[first:end] = blank
        offset = end
    return "".join(uncommented), "".join(code)


def definition_span(code, declaration):
    """Find the top-level initializer, skipping array types and nested blocks."""
    depth = 0
    initializer = None
    for token in DELIMITER.finditer(code, declaration.end()):
        value = token[0]
        if value in "([{":
            depth += 1
        elif value in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and value == "=" and initializer is None:
            initializer = token.end()
        elif depth == 0 and value == ";":
            return None if initializer is None else (initializer, token.start())
    return None


def locations(code, uncommented, anchor):
    require(anchor and anchor == anchor.strip(), "invalid empty or padded source anchor")
    pattern = re.escape(anchor)
    if re.match(r"\w", anchor[0]):
        pattern = r"(?<!\w)" + pattern
    if re.match(r"\w", anchor[-1]):
        pattern += r"(?!\w)"
    # A quoted copy of the expression is not a use. The anchor may itself
    # include literals after its first Rust token, as in digest.update(b"...").
    return [match for match in re.finditer(pattern, uncommented) if not code[match.start()].isspace()]


def workspace_sources(root):
    cargo = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--offline", "--locked", "--no-deps", "--format-version", "1"], cwd=root,
    ))
    members = set(cargo["workspace_members"])
    packages = [package for package in cargo["packages"] if package["id"] in members]
    manifests = {}
    targets = {}
    for package in packages:
        manifest = root.joinpath(package["manifest_path"]).relative_to(root)
        manifests[str(manifest)] = sorted(package["features"])
        for target in package["targets"]:
            path = str(root.joinpath(target["src_path"]).relative_to(root))
            targets[path] = sorted(target["kind"])
    roots = [manifest.removesuffix("Cargo.toml") for manifest in manifests]
    files = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root,
    ).decode().split("\0")
    paths = sorted({path for path in files if path and (root / path).is_file()})
    sources = {
        path: (root / path).read_text(encoding="utf-8")
        for path in paths
        if path.endswith(".rs") and (path in targets or any(path.startswith(r) for r in roots))
    }
    inventory = {
        "cargo_packages": len(manifests),
        "cargo_targets": len(targets),
        "rust_outside_workspace_files": [
            path for path in paths if path.endswith(".rs") and path not in sources and not path.startswith("vendor/")
        ],
        "non_rust_inventory": {
            "assembly_or_linker_files": [path for path in paths if path.endswith(NATIVE_SUFFIXES)
                                         and not path.startswith("vendor/")],
            "tool_sources": [path for path in paths if path.startswith(("tools/", "tests/", ".github/workflows/"))
                             and path.endswith((".py", ".sh", ".yml", ".yaml"))],
        },
    }
    return sources, inventory, manifests


def source_location(path, text, start, **fields):
    return {"file": path, "line": text.count("\n", 0, start) + 1, **fields}


def test_cases(root, path, rust_syntax):
    if path.endswith(".py"):
        tree = ast.parse((root / path).read_bytes(), filename=path)
        return {node.name: node.lineno for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    _, code = rust_syntax.get(path, ("", ""))
    return {case[1]: code.count("\n", 0, case.start(1)) + 1 for case in RUST_TEST.finditer(code)}


def verify(root=ROOT, *, include_candidates=False):
    root = root.resolve()
    baseline = (root / BASELINE).read_bytes()
    registry_wire = (root / REGISTRY).read_bytes()
    registered = registry_owners(baseline)
    registry = strict_json(registry_wire)
    require(registry["schema"] == "cyxia-v020-g1-parameter-bindings/v1", "invalid parameter binding schema")
    sources, scope, manifests = workspace_sources(root)
    syntax = {path: mask_rust(source) for path, source in sources.items()}
    declarations = {path: list(DECLARATION.finditer(code)) for path, (_, code) in syntax.items()}
    checked_spans = {path: [] for path in sources}
    anchored = set()
    symbol_keys = defaultdict(list)
    bindings = registry["bindings"]
    require(bindings, "missing registered parameter bindings")
    uses = []
    definitions = []
    verified_tests = []
    known_cases = {}
    for key, binding in bindings.items():
        require(registered.get(key) == binding["owner"] and binding["unit"].strip()
                and binding["derivation"].strip(), f"unregistered or incomplete parameter binding {key}")
        require(all(binding[field] for field in ("definitions", "uses", "tests")), f"missing evidence for {key}")
        for path, name, expression in binding["definitions"]:
            identity = (path, name)
            matching = [entry for entry in declarations.get(path, ()) if entry[1] == name]
            require(len(matching) == 1 and identity not in anchored, f"ambiguous or missing parameter {path}:{name}")
            uncommented, code = syntax[path]
            span = definition_span(code, matching[0])
            require(span is not None and uncommented[slice(*span)].strip() == expression,
                    f"changed definition for {key}: {path}:{name}")
            checked_spans[path].append((matching[0].start(), span[1]))
            anchored.add(identity)
            definitions.append(source_location(path, code, matching[0].start(), key=key, item=name))
            if key not in symbol_keys[name]:
                symbol_keys[name].append(key)
        for path, anchor in binding["uses"]:
            uncommented, code = syntax.get(path, ("", ""))
            matches = locations(code, uncommented, anchor)
            require(matches, f"missing use of {key} in {path}")
            checked_spans[path].extend(match.span() for match in matches)
            uses.append({"key": key, "file": path,
                         "lines": [code.count("\n", 0, match.start()) + 1 for match in matches]})
        for path, case in binding["tests"]:
            if path not in known_cases:
                known_cases[path] = test_cases(root, path, syntax)
            require(case in known_cases[path], f"missing test entry for {key}: {path}:{case}")
            verified_tests.append({"key": key, "file": path, "line": known_cases[path][case], "case": case})

    unresolved = []
    references = []
    literals = []
    cfg = []
    includes = []
    symbols = re.compile(r"\b(?:" + "|".join(map(re.escape, sorted(symbol_keys))) + r")\b")
    for path, (_, code) in syntax.items():
        unresolved.extend(source_location(path, code, match.start(), item=match[1])
                          for match in declarations[path] if (path, match[1]) not in anchored)
        confirmed = checked_spans[path]
        for match in symbols.finditer(code):
            if not any(first <= match.start() and match.end() <= end for first, end in confirmed):
                references.append(source_location(path, code, match.start(), item=match[0],
                                                   possible_keys=symbol_keys[match[0]]))
        for match in NUMBER.finditer(code):
            if not any(first <= match.start() and match.end() <= end for first, end in confirmed):
                literals.append(source_location(path, code, match.start(), literal=match[0],
                                                column=match.start() - code.rfind("\n", 0, match.start())))
        cfg.extend(source_location(path, code, match.start()) for match in CFG.finditer(code))
        includes.extend(source_location(path, code, match.start()) for match in GENERATED.finditer(code))
    report = {"status": "OPEN", "scope": "Checked Rust anchors and lexical Rust inventory for all workspace targets",
              "baseline_sha256": sha256(baseline).hexdigest(), "bindings_sha256": sha256(registry_wire).hexdigest(),
              "source_files": len(sources), "registered_baseline_keys": len(registered),
              "verified_registered_bindings": len(bindings), "verified_use_anchors": len(uses), "verified_uses": uses,
              "verified_definitions": definitions, "test_entry_points": verified_tests,
              "unmapped_baseline_keys": sorted(set(registered) - set(bindings)),
              "unclassified_named_declarations": len(unresolved), "unclassified_named_references": len(references),
              "unclassified_numeric_occurrences": len(literals),
              "cfg_annotations": len(cfg), "include_calls": len(includes), **scope}
    if include_candidates:
        report.update(declaration_candidates=unresolved, numeric_candidates=literals, cfg_locations=cfg,
                      reference_candidates=references, include_locations=includes, cargo_manifest_features=manifests)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list-candidates", action="store_true", help="include unresolved declarations, literals and conditional source locations")
    parser.add_argument("--require-complete", action="store_true", help="fail while any G1 source-use evidence remains open")
    args = parser.parse_args()
    try:
        report = verify(include_candidates=args.list_candidates)
    except (KeyError, OSError, SyntaxError, TypeError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"G1 parameter binding check failed: {error}\n")
    print(json.dumps(report, indent=2))
    if args.require_complete and report["status"] != "PASS":
        parser.exit(1, "G1 parameter use is OPEN; the report lists unmapped keys and unclassified source.\n")


if __name__ == "__main__":
    main()
