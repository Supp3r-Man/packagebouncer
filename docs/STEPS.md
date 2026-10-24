# Steps

1. `python scan.py fixtures` parses `fixtures/package.json` and `fixtures/requirements.txt`, scores every dependency, writes `out/scan.json` and refreshes `report.html`.
2. Open `report.html`: graph colored by risk, sortable table, and a "Why flagged" panel for the selected dependency.
3. `python sbom.py` turns `out/scan.json` into a CycloneDX SBOM at `out/sbom.json`.
4. `python diff.py fixtures/sbom_prev.json out/sbom.json` flags what is new or changed since the older SBOM (add `--strict` to exit 1).
5. `pytest` runs the typosquat and install-script tests.
6. Tune: edit weights in `score.py` or thresholds at the top of `scan.py`, rerun step 1, and watch which dependencies move.
7. Point it at your own manifests with `python scan.py path/to/project --metadata your_metadata.json`. Without metadata the age, download and maintainer checks stay quiet (every package reads as "no metadata").

All fixture names (`lodahs`, `reqeusts`, ...) and all fixture data are invented, inert text. Do not install them.

# Interview Q&A

**1. What is dependency confusion?**
A build resolves an internal package name from a public registry because the public one has a higher version or is checked first. An attacker publishes that name publicly and gets code execution in CI or on developer machines. Defenses: scoped or namespaced internal packages, registry configuration that pins internal scopes to the private registry, reserving your names on public registries, and failing the build when a private name resolves publicly. This tool flags direct URL sources and unknown packages but does not know which names are internal.

**2. How does typosquatting work and how do you detect it?**
Attackers publish names one slip away from popular ones (`reqeusts`), or with lookalike characters (`c0lorama`, `nurnpy`), and wait for a typo or a copied command. Detection compares candidates against known-popular names with edit distance (counting swaps as one edit) and a homoglyph fold. It is cheap but noisy: legitimate unlisted packages can sit near popular ones, so thresholds depend on name length and a high download count exempts a name.

**3. Why are install scripts risky?**
`preinstall`, `install` and `postinstall` run arbitrary code with the installing user's privileges, before anyone has reviewed the package, including on CI runners that hold secrets. Mitigations: `npm install --ignore-scripts` (with an allow-list for packages that truly need a build), reviewing scripts of new or changed dependencies, and sandboxed installs. Download-and-pipe, base64 decoding and eval are the telltale patterns, but plenty of honest packages compile native code in `install`, which is why the base flag is low weight.

**4. Lockfiles and pinning: what do they buy you?**
A lockfile records the exact resolved version (and integrity hash) of every transitive dependency, so installs are reproducible and a malicious new release does not slide in on the next build. Ranges such as `^1.2.3` or `>=2.0` mean your build changes without a code change. Pin exactly or commit lockfiles, install with `npm ci` or `pip install --require-hashes`, and update on purpose through reviewed pull requests. Pinning does not make a bad version safe; it makes changes visible.

**5. What is an SBOM for?**
It is an inventory of what is inside a build: components, versions, identifiers (purl) and relationships. When a new vulnerability or a compromised package is announced, you can answer "are we affected, and where?" in minutes instead of days. Diffing two SBOMs also shows what changed between releases. Value depends on accuracy: an SBOM built from declared ranges rather than resolved versions, like this MVP's, is only a starting point.

**6. What are SLSA and provenance?**
SLSA is a framework of levels for build integrity. Provenance is signed metadata saying which source, builder and steps produced an artifact. Consumers verify it so a tampered upload that does not match the claimed source and pipeline gets rejected. Related tools: Sigstore signatures, npm provenance attestations, and trusted publishing for PyPI. It answers "was this built from the repo it claims", which name-based heuristics cannot.

**7. How do you handle false positives?**
Expect them: new internal packages look "very new", small niche libraries have few downloads, and real maintainers hand projects over. Keep reasons visible (the "Why flagged" panel), score with several weak signals rather than one strong rule, use allow-lists with an owner and an expiry date, and track precision on reviewed findings. Use the score to prioritize human review rather than to block automatically, except for the strongest combinations.

**8. What would you add for production?**
Real registry metadata (publish dates, maintainers, download counts) with caching; lockfile parsing for resolved versions and integrity hashes; `setup.py`, wheel and `prepare` hook analysis; a much larger and regularly refreshed popular-names list; known-vulnerability data (OSV) and license checks; internal-name protection against dependency confusion; provenance and signature verification; CI integration with PR comments, baselines and an allow-list workflow; sandboxed dynamic analysis for the riskiest packages; and evaluation against labelled real-world malicious packages to tune weights.
