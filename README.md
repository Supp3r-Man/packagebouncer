# PackageBouncer
**🛃 Nothing gets into your project without showing ID.**
## What it does
Reads `package.json` and `requirements.txt`, flags typosquats, shady install scripts, loose pins and brand-new packages, scores each 0-100 and draws a risk graph. Offline, never installs a thing, concept only.
## Run it
`python scan.py fixtures`, open `report.html`, then `python sbom.py` and `python diff.py fixtures/sbom_prev.json out/sbom.json`. `pytest` runs the tests.
## Most suspicious name we caught
`lodahs`: lodash after a rough night, with a `curl | sh` postinstall for company. Fixture only, so please don't `npm install` it.
## Honest disclaimer
Heuristics, not a verdict. Expect false positives and misses; a human still makes the call.
## Things that went wrong while building this
- Nothing was run during the build, so your first `pytest` may find a typo before any attacker does.
- The "top 500" list was typed from memory, not downloaded, so it is popular-ish rather than official.

Be suspicious of names, kind to maintainers, and pin your versions. ☕
