"""PackageBouncer: static dependency scanner.

Reads manifests plus local fixture files only. It never installs, imports, executes or downloads anything.
Usage: python scan.py [PATH ...] [--metadata F] [--packages DIR] [--top F] [--out F] [--report F]
"""
import argparse
import json
import math
import re
from collections import Counter
from datetime import date
from itertools import islice, product
from pathlib import Path

from score import score_dependency

ROOT = Path(__file__).resolve().parent
MARK = re.compile(r"/\*DATA\*/.*?/\*END\*/", re.S)

POPULAR_DOWNLOADS = 1_000_000  # above this a lookalike name is assumed to be legitimate
NEW_DAYS = 30
LOW_DOWNLOADS = 1000
MAX_DEPTH = 5

NPM_EXACT = re.compile(r"^=?v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$")
DIRECT_RE = re.compile(r"^(git\+|git://|ssh://|https?://|file:|link:|github:|gitlab:|bitbucket:|\.{0,2}/|[\w.-]+/[\w.-]+$)")
REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*([<>=!~][^;]*)?")

CONFUSABLES = {
    "0": "o", "1": "li", "3": "e", "4": "a", "5": "s", "$": "s",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "і": "i", "ѕ": "s",  # Cyrillic lookalikes
}
MULTI = (("rn", "m"), ("vv", "w"), ("cl", "d"))

INSTALL_HOOKS = ("preinstall", "install", "postinstall")
DOWNLOAD_RE = re.compile(r"\b(curl|wget|invoke-webrequest|iwr|certutil|bitsadmin)\b", re.I)
ENCODED_RE = re.compile(r"base64\s+(-d|--decode)|\batob\s*\(|base64['\"]\s*\)|frombase64string", re.I)
EXEC_RE = re.compile(r"\beval\b|\|\s*(sh|bash|zsh|pwsh|powershell)\b|\bnode\s+-e\b|\bpython3?\s+-c\b|\bchild_process\b", re.I)

LITERAL_RE = re.compile(r"""(["'`])([^"'`\\\n]{40,})\1""")
HEXESC_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")
IDENT_RE = re.compile(r"\b_0x[0-9a-f]{4,6}\b")


# -- parsing ----------------------------------------------------------------
def normalize_name(ecosystem, name):
    name = name.strip().lower()
    return re.sub(r"[-_.]+", "-", name) if ecosystem == "pypi" else name


def parse_package_json(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    deps = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            deps.append(("npm", name, str(spec), section))
    return deps


def parse_requirements(path):
    deps = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-")):
            continue
        if DIRECT_RE.match(line) or "://" in line:
            name = line.rsplit("/", 1)[-1].split("@")[0].split("#")[0].removesuffix(".git") or line
            deps.append(("pypi", name, line, "requirements"))
            continue
        m = REQ_RE.match(line)
        if m:
            deps.append(("pypi", m.group(1), (m.group(2) or "").strip(), "requirements"))
    return deps


def classify_spec(ecosystem, spec):
    """Return 'pinned', 'unpinned', 'any' (accepts anything) or 'direct' (URL, VCS or path source)."""
    s = spec.strip()
    if DIRECT_RE.match(s):
        return "direct"
    if ecosystem == "npm":
        if s in ("", "*", "latest", "x", "next"):
            return "any"
        return "pinned" if NPM_EXACT.match(s) else "unpinned"
    if s == "":
        return "any"
    return "pinned" if re.fullmatch(r"===?\s*[\w.+!-]+", s) else "unpinned"


# -- typosquat --------------------------------------------------------------
def load_top(path):
    """Names are whitespace separated, grouped under [npm] and [pypi] headers."""
    top, eco = {"npm": set(), "pypi": set()}, None
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            eco = line.strip("[]")
            continue
        top[eco].update(normalize_name(eco, n) for n in line.split())
    return top


def edit_distance(a, b):
    """Optimal string alignment distance: insert, delete, substitute and adjacent swap each cost 1."""
    prev2, prev = None, list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] != b[j - 1]))
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


def homoglyph_candidates(name):
    """Names this one could be pretending to be, after undoing common lookalike characters."""
    options = [CONFUSABLES.get(c, c) for c in name]
    cands = {"".join(p) for p in islice(product(*options), 256)}
    for c in list(cands):
        for a, b in MULTI:
            if a in c:
                cands.add(c.replace(a, b))
    cands.discard(name)
    return cands


def check_typosquat(ecosystem, name, top, weekly_downloads=None):
    """Return a reason dict if the name looks like a lookalike of a popular package, else None."""
    if name.startswith("@"):  # scoped npm names belong to an org; this heuristic skips them
        return None
    norm, names = normalize_name(ecosystem, name), top[ecosystem]
    if norm in names or (weekly_downloads or 0) >= POPULAR_DOWNLOADS:
        return None
    hits = sorted(homoglyph_candidates(norm) & names)
    if hits:
        return {"code": "typosquat_homoglyph", "detail": f"'{name}' swaps in lookalike characters for popular '{hits[0]}'"}
    near = sorted((edit_distance(norm, t), t) for t in names if abs(len(t) - len(norm)) <= 2)
    for dist, target in near:
        if dist == 1 and len(target) >= 5:
            return {"code": "typosquat_edit1", "detail": f"'{name}' is 1 edit away from popular '{target}'"}
        if dist == 2 and len(target) >= 8:
            return {"code": "typosquat_edit2", "detail": f"'{name}' is 2 edits away from popular '{target}'"}
        if dist > 2:
            break
    return None


# -- install scripts and source ----------------------------------------------
def check_install_scripts(scripts):
    """scripts: the 'scripts' map of a package.json. Looks only at install-time hooks; text is never run."""
    reasons = []
    for hook in INSTALL_HOOKS:
        cmd = (scripts or {}).get(hook)
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        snippet = f"{hook}: {cmd.strip()[:80]}"
        reasons.append({"code": "install_script", "detail": f"runs at install time - {snippet}"})
        for code, rx in (("install_script_download", DOWNLOAD_RE), ("install_script_encoded", ENCODED_RE),
                         ("install_script_exec", EXEC_RE)):
            if rx.search(cmd):
                reasons.append({"code": code, "detail": snippet})
    return reasons


def shannon_entropy(s):
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values()) if n else 0.0


def find_obfuscation(text):
    found = []
    for m in LITERAL_RE.finditer(text):
        lit = m.group(2)
        if " " not in lit and shannon_entropy(lit) >= 4.5:
            found.append(f"high-entropy string ({len(lit)} chars, {shannon_entropy(lit):.1f} bits/char)")
    if HEXESC_RE.search(text):
        found.append("long run of \\x escapes")
    if len(IDENT_RE.findall(text)) >= 3:
        found.append("obfuscator-style _0x identifiers")
    return found


# -- metadata ---------------------------------------------------------------
def load_metadata(path):
    p = Path(path)
    if not p.is_file():
        return date.today(), {}
    data = json.loads(p.read_text(encoding="utf-8"))
    as_of = date.fromisoformat(data["as_of"]) if data.get("as_of") else date.today()
    return as_of, data.get("packages", {})


def check_metadata(meta, as_of):
    if meta is None:
        return [{"code": "no_metadata", "detail": "not in local metadata.json (offline, so unknown)"}]
    reasons = []
    if meta.get("first_published"):
        age = (as_of - date.fromisoformat(meta["first_published"])).days
        if age < NEW_DAYS:
            reasons.append({"code": "very_new", "detail": f"first published {age} days before the scan date"})
    downloads = meta.get("weekly_downloads")
    if downloads is not None and downloads < LOW_DOWNLOADS:
        reasons.append({"code": "low_downloads", "detail": f"{downloads} downloads per week"})
    prev, cur = meta.get("previous_maintainers"), meta.get("maintainers")
    if prev and cur and set(prev) != set(cur):
        reasons.append({"code": "maintainer_change", "detail": f"maintainers changed: {sorted(prev)} -> {sorted(cur)}"})
    return reasons


def read_package_contents(packages_dir, ecosystem, name):
    """Return (install scripts, sample source) from fixtures/packages/<eco>/<name>/. Plain reads only."""
    norm = normalize_name(ecosystem, name)
    if ".." in norm.split("/") or norm.startswith("/") or "\\" in norm or ":" in norm:
        return {}, ""
    root = Path(packages_dir).resolve()
    base = (root / ecosystem / norm).resolve()
    if not base.is_relative_to(root):
        return {}, ""
    scripts, source = {}, ""
    if (base / "package.json").is_file():
        scripts = json.loads((base / "package.json").read_text(encoding="utf-8")).get("scripts") or {}
    if (base / "sample_source.txt").is_file():
        source = (base / "sample_source.txt").read_text(encoding="utf-8", errors="replace")
    return scripts, source


# -- pipeline ---------------------------------------------------------------
def build_graph(direct, packages, max_depth=MAX_DEPTH):
    nodes, edges = {}, set()
    todo = [("root", eco, name, spec, section, 1) for eco, name, spec, section in direct]
    while todo:
        parent, eco, name, spec, section, depth = todo.pop(0)
        nid = f"{eco}:{normalize_name(eco, name)}"
        edges.add((parent, nid))
        if nid in nodes:
            continue
        nodes[nid] = {"id": nid, "name": name, "ecosystem": eco, "spec": spec, "section": section, "depth": depth}
        if depth < max_depth:
            for child in (packages.get(nid) or {}).get("requires", []):
                todo.append((nid, eco, child, None, "transitive", depth + 1))
    return nodes, edges


def analyze(node, ctx):
    eco, name, spec = node["ecosystem"], node["name"], node["spec"]
    meta = ctx["packages"].get(node["id"])
    reasons = []
    hit = check_typosquat(eco, name, ctx["top"], (meta or {}).get("weekly_downloads"))
    if hit:
        reasons.append(hit)
    scripts, source = read_package_contents(ctx["packages_dir"], eco, name)
    reasons += check_install_scripts(scripts)
    reasons += [{"code": "obfuscated_source", "detail": d} for d in find_obfuscation(source)]
    if spec is not None:  # transitive dependencies have no declared spec to judge
        kind = classify_spec(eco, spec)
        if kind == "direct":
            reasons.append({"code": "direct_source", "detail": f"declared as {spec[:80]}"})
        elif kind == "any":
            reasons.append({"code": "unpinned_any", "detail": f"declared as '{spec or '(no version)'}' - any version is accepted"})
        elif kind == "unpinned":
            reasons.append({"code": "unpinned", "detail": f"declared as '{spec}' - resolves to different versions over time"})
    return reasons + check_metadata(meta, ctx["as_of"])


def scan(direct, ctx):
    nodes, edges = build_graph(direct, ctx["packages"])
    deps = []
    for node in nodes.values():
        node["score"], node["level"], node["reasons"] = score_dependency(analyze(node, ctx))
        deps.append(node)
    deps.sort(key=lambda d: (-d["score"], d["id"]))
    return deps, sorted(edges)


def collect_direct(paths):
    direct, sources = [], []
    for p in map(Path, paths):
        for f in ([p / "package.json", p / "requirements.txt"] if p.is_dir() else [p]):
            if not f.is_file():
                continue
            if f.name == "package.json":
                direct += parse_package_json(f)
            elif f.suffix == ".txt":
                direct += parse_requirements(f)
            else:
                continue
            sources.append(str(f))
    if not sources:
        raise SystemExit("no package.json or requirements.txt found")
    return direct, sources


def refresh_report(path, result):
    p = Path(path)
    if not p.exists():
        return
    payload = json.dumps({"dependencies": result["dependencies"], "edges": result["edges"]}).replace("</", "<\\/")
    p.write_text(MARK.sub(lambda _: f"/*DATA*/{payload}/*END*/", p.read_text(encoding="utf-8")), encoding="utf-8")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("paths", nargs="*", default=[str(ROOT / "fixtures")])
    p.add_argument("--metadata", default=str(ROOT / "fixtures" / "metadata.json"))
    p.add_argument("--packages", default=str(ROOT / "fixtures" / "packages"))
    p.add_argument("--top", default=str(ROOT / "data" / "top_packages.txt"))
    p.add_argument("--out", default=str(ROOT / "out" / "scan.json"))
    p.add_argument("--report", default=str(ROOT / "report.html"))
    args = p.parse_args(argv)
    direct, sources = collect_direct(args.paths)
    as_of, packages = load_metadata(args.metadata)
    ctx = {"packages": packages, "as_of": as_of, "top": load_top(args.top), "packages_dir": args.packages}
    deps, edges = scan(direct, ctx)
    result = {"project": Path(args.paths[0]).resolve().name, "as_of": as_of.isoformat(), "sources": sources,
              "dependencies": deps, "edges": edges}
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    refresh_report(args.report, result)
    print(f"{len(deps)} dependencies scanned -> {out}")
    for d in deps[:5]:
        print(f"  {d['score']:3d} {d['level']:<8} {d['id']}")


if __name__ == "__main__":
    main()
