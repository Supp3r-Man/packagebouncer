"""Weighted risk scoring. Every reason code carries a weight; a dependency's score combines the
distinct codes noisy-OR style, so it stays within 0-100 and more evidence always pushes it higher."""

WEIGHTS = {
    "typosquat_homoglyph": 70,
    "typosquat_edit1": 60,
    "typosquat_edit2": 35,
    "install_script": 10,
    "install_script_download": 40,
    "install_script_encoded": 35,
    "install_script_exec": 35,
    "obfuscated_source": 40,
    "maintainer_change": 35,
    "very_new": 30,
    "low_downloads": 25,
    "direct_source": 25,
    "unpinned_any": 20,
    "unpinned": 10,
    "no_metadata": 3,
}

LABELS = {
    "typosquat_homoglyph": "Lookalike characters in a popular name",
    "typosquat_edit1": "One edit away from a popular name",
    "typosquat_edit2": "Two edits away from a popular name",
    "install_script": "Runs a script at install time",
    "install_script_download": "Install script downloads something",
    "install_script_encoded": "Install script decodes base64",
    "install_script_exec": "Install script evals or pipes into a shell",
    "obfuscated_source": "Obfuscated or high-entropy source",
    "maintainer_change": "Maintainers changed",
    "very_new": "Very new package",
    "low_downloads": "Very few downloads",
    "direct_source": "Installed from a URL, VCS or path",
    "unpinned_any": "Accepts any version",
    "unpinned": "Version not pinned",
    "no_metadata": "No registry metadata available",
}

LEVELS = ((75, "critical"), (50, "high"), (20, "medium"), (0, "low"))


def level_for(score):
    return next(name for floor, name in LEVELS if score >= floor)


def score_dependency(reasons):
    """reasons: [{code, detail}]. Returns (score 0-100, level, reasons with weight + label, heaviest first)."""
    enriched = [{**r, "weight": WEIGHTS.get(r["code"], 0), "label": LABELS.get(r["code"], r["code"])} for r in reasons]
    enriched.sort(key=lambda r: -r["weight"])
    seen, survive = set(), 1.0
    for r in enriched:
        if r["code"] in seen:
            continue
        seen.add(r["code"])
        survive *= 1 - r["weight"] / 100
    score = round(100 * (1 - survive))
    return score, level_for(score), enriched
