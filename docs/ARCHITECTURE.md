# Architecture

```
 package.json ----+
                  +--> parse --> build graph --> checks (per dependency) --> score.py --> out/scan.json
 requirements.txt-+     |            ^                 ^   ^   ^                              |
                        |            |                 |   |   |                              +--> report.html
 fixtures/metadata.json +------------+  typosquat -----+   |   |                              |    (graph, table,
   (registry facts, requires edges)       install scripts --+   |                              |     why-flagged)
 fixtures/packages/<eco>/<name>/          obfuscation ----------+                              |
   (package.json scripts, sample_source.txt)  age / downloads / maintainers                    +--> sbom.py --> out/sbom.json
 data/top_packages.txt (popular names) ---^                                                         |
                                                                                                    v
                                                                 older SBOM --------------------> diff.py
                                                                                       (new / changed / removed)
```

Everything is read from local files. The scanner never installs, imports, executes or downloads a package; "install script" checks are regexes over the script text.

## Pipeline

1. **Parse**: `package.json` (dependencies, devDependencies, optionalDependencies) and `requirements.txt` become `(ecosystem, name, spec, section)` tuples.
2. **Graph**: `metadata.json` lists each package's `requires`, so transitive dependencies are walked breadth first (depth cap 5). Each node is `ecosystem:normalized-name`.
3. **Checks** (each returns reasons `{code, detail}`):
   - typosquat: homoglyph folding first, then optimal-string-alignment edit distance (swaps count as one edit) against the popular-names list. Skipped for exact matches, scoped npm names, and packages above 1M weekly downloads.
   - install scripts: `preinstall`, `install`, `postinstall` text checked for download, base64 decode, and eval or pipe-to-shell patterns.
   - obfuscation: high-entropy string literals, long `\x` runs, `_0x` identifiers in the bundled sample source.
   - pinning: exact versions pass; ranges, wildcards and URL/VCS sources are flagged (declared dependencies only).
   - metadata: first published under 30 days, under 1,000 weekly downloads, maintainer set changed, or no entry at all.
4. **Score** (`score.py`): each distinct reason code has a weight; the score is `100 * (1 - product(1 - w/100))`, so it stays 0-100 and extra evidence always raises it. Levels: low <20, medium 20-49, high 50-74, critical 75+.
5. **Outputs**: `out/scan.json`; `scan.py` also rewrites the JSON between `/*DATA*/` and `/*END*/` in `report.html`, so the dashboard is one offline file.
6. **SBOM**: `sbom.py` emits CycloneDX 1.5 (components, purls, dependency edges, risk properties). Versions appear only when pinned; otherwise the declared spec is a property.
7. **Diff**: `diff.py` keys components by purl without version and reports NEW, CHANGED (version or spec differs, or risk rose by 10+) and REMOVED.

## Not covered

Lockfile parsing, `setup.py` or wheel install hooks, real registry lookups (`--online` is future work), license checks, known-CVE matching.
