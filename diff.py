"""Compare two PackageBouncer SBOMs and flag new, removed or changed dependencies.

Usage: python diff.py OLD.json NEW.json [--strict]
--strict exits with status 1 when anything new or changed is found (handy as a gate).
"""
import argparse
import json
import sys
from pathlib import Path

RISK_JUMP = 10


def component_key(comp):
    return comp["purl"].split("@")[0]  # purl without version; '@' in scoped names is %40-encoded


def props(comp):
    return {p["name"]: p["value"] for p in comp.get("properties", [])}


def describe(comp):
    return comp.get("version") or f"spec {props(comp).get('packagebouncer:declared_spec', '?')}"


def score(comp):
    return int(props(comp).get("packagebouncer:risk_score", 0))


def diff_sboms(old, new):
    o = {component_key(c): c for c in old.get("components", [])}
    n = {component_key(c): c for c in new.get("components", [])}
    out = {"new": [], "removed": [], "changed": []}
    for k in sorted(n.keys() - o.keys()):
        out["new"].append({"name": n[k]["name"], "to": describe(n[k]), "score": score(n[k])})
    for k in sorted(o.keys() - n.keys()):
        out["removed"].append({"name": o[k]["name"], "from": describe(o[k])})
    for k in sorted(n.keys() & o.keys()):
        a, b = o[k], n[k]
        if describe(a) != describe(b) or score(b) - score(a) >= RISK_JUMP:
            out["changed"].append({"name": b["name"], "from": describe(a), "to": describe(b),
                                   "score_from": score(a), "score_to": score(b)})
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("old")
    p.add_argument("new")
    p.add_argument("--strict", action="store_true")
    args = p.parse_args(argv)
    d = diff_sboms(*(json.loads(Path(f).read_text(encoding="utf-8")) for f in (args.old, args.new)))
    for c in d["new"]:
        print(f"NEW      {c['name']:<20} {c['to']:<18} risk {c['score']}")
    for c in d["changed"]:
        print(f"CHANGED  {c['name']:<20} {c['from']} -> {c['to']}  risk {c['score_from']} -> {c['score_to']}")
    for c in d["removed"]:
        print(f"REMOVED  {c['name']:<20} {c['from']}")
    print(f"{len(d['new'])} new, {len(d['changed'])} changed, {len(d['removed'])} removed")
    if args.strict and (d["new"] or d["changed"]):
        sys.exit(1)


if __name__ == "__main__":
    main()
