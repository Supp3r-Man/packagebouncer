"""Emit a minimal CycloneDX 1.5 JSON SBOM from a PackageBouncer scan result.

Usage: python sbom.py [out/scan.json] [--out out/sbom.json]
Versions are only filled in when the manifest pins one; otherwise the declared spec is kept as a property.
"""
import argparse
import json
import re
from pathlib import Path
from urllib.parse import quote

from scan import classify_spec

ROOT = Path(__file__).resolve().parent


def purl(ecosystem, name, version=None):
    base = f"pkg:{ecosystem}/{quote(name, safe='/')}"
    return f"{base}@{quote(version)}" if version else base


def resolved_version(dep):
    spec = dep.get("spec")
    if not spec or classify_spec(dep["ecosystem"], spec) != "pinned":
        return None
    return re.sub(r"^(===?|=|v)\s*", "", spec.strip())


def build_sbom(scan):
    refs, components = {}, []
    for dep in scan["dependencies"]:
        version = resolved_version(dep)
        ref = purl(dep["ecosystem"], dep["id"].split(":", 1)[1], version)
        refs[dep["id"]] = ref
        comp = {"type": "library", "bom-ref": ref, "name": dep["name"], "purl": ref,
                "properties": [{"name": "packagebouncer:risk_score", "value": str(dep["score"])},
                               {"name": "packagebouncer:risk_level", "value": dep["level"]}]}
        if version:
            comp["version"] = version
        elif dep.get("spec") is not None:
            comp["properties"].append({"name": "packagebouncer:declared_spec", "value": dep["spec"] or "(none)"})
        components.append(comp)
    depends = {}
    for parent, child in scan["edges"]:
        depends.setdefault("root" if parent == "root" else refs[parent], []).append(refs[child])
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "packagebouncer"}]},
            "component": {"type": "application", "name": scan["project"], "bom-ref": "root"},
        },
        "components": sorted(components, key=lambda c: c["purl"]),
        "dependencies": [{"ref": r, "dependsOn": sorted(d)} for r, d in sorted(depends.items())],
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("scan", nargs="?", default=str(ROOT / "out" / "scan.json"))
    p.add_argument("--out", default=str(ROOT / "out" / "sbom.json"))
    args = p.parse_args(argv)
    sbom = build_sbom(json.loads(Path(args.scan).read_text(encoding="utf-8")))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
    print(f"{len(sbom['components'])} components -> {out}")


if __name__ == "__main__":
    main()
