"""The key register loader (soc_api.rotate.keys): what it accepts, and that a problem never
echoes a file's contents."""

from pathlib import Path

import pytest
from rotate_support import key_text, make_register

from soc_api.rotate.keys import (
    MAX_FILE_BYTES,
    MAX_FILES,
    Register,
    load_register,
    parse_key,
    printable,
)


def load(tmp_path: Path, files: dict[str, str], sub: str = "r") -> Register:
    """Load a register built in its own sub folder, so one test can build several."""
    root = tmp_path / sub
    root.mkdir()
    return load_register(make_register(root, files))


def test_a_manual_and_an_automatic_key_are_read(tmp_path: Path) -> None:
    reg = load(
        tmp_path,
        {
            "n8n-customer": key_text("n8n-customer"),
            "posture": key_text("posture", method="automatic"),
        },
    )
    assert reg.problems == []
    key = reg.keys["n8n-customer"]
    assert (key.method, key.sensitive, key.period_days, key.ready) == ("manual", False, 90, True)
    assert key.check == "Prove it works"
    assert reg.keys["posture"].method == "automatic"


def test_period_must_match_sensitivity(tmp_path: Path) -> None:
    ok = load(tmp_path, {"a-key": key_text("a-key", sensitive=True)}, "ok")
    assert ok.problems == [] and ok.keys["a-key"].period_days == 30
    wrong_sensitive = load(tmp_path, {"a-key": key_text("a-key", sensitive=True, period=90)}, "s")
    assert any("period_days must be 30" in p for p in wrong_sensitive.problems)
    wrong_standard = load(tmp_path, {"a-key": key_text("a-key", period=60)}, "t")
    assert any("period_days must be 90" in p for p in wrong_standard.problems)


def test_a_key_replaced_only_on_exposure_has_no_period(tmp_path: Path) -> None:
    ok = load(tmp_path, {"age-key": key_text("age-key", method="none")}, "ok")
    assert ok.problems == [] and ok.keys["age-key"].period_days is None
    bad = load(tmp_path, {"age-key": key_text("age-key", method="none", period=90)}, "bad")
    assert any("period_days is not allowed" in p for p in bad.problems)


def test_ready_defaults_to_true_and_can_be_false(tmp_path: Path) -> None:
    reg = load_register(
        make_register(
            tmp_path,
            {"a-key": key_text("a-key"), "b-key": key_text("b-key", ready=False)},
        )
    )
    assert reg.keys["a-key"].ready is True and reg.keys["b-key"].ready is False


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        (key_text("other-name"), "id must equal the file name"),
        (key_text("Bad_Id!"), "id must be lowercase"),
        (key_text("a-key").replace('method = "manual"', 'method = "sometimes"'), "method must be"),
        (key_text("a-key").replace("sensitive = false", 'sensitive = "no"'), "sensitive must be"),
        (key_text("a-key").replace('name = "A key"', 'name = ""'), "name must be non-empty"),
        (
            key_text("a-key").replace('vendor = "limacharlie"', 'vendor = "Evil Corp"'),
            "vendor must be",
        ),
        (key_text("a-key", ready=False).replace("ready = false", 'ready = "yes"'), "ready must be"),
    ],
)
def test_each_wrong_field_is_named(tmp_path: Path, text: str, fragment: str) -> None:
    reg = load_register(make_register(tmp_path, {"a-key": text}))
    assert any(fragment in p for p in reg.problems), reg.problems
    assert reg.keys == {}


def test_a_problem_never_echoes_what_the_file_holds(tmp_path: Path) -> None:
    secret = "VALUE-that-must-never-be-printed-9f8e7d6c5b4a"
    broken = f'id = "{secret}"\nname = "{secret}\n'  # unterminated string: not valid TOML
    odd = key_text("odd-key", extra=f'vendor_note = "{secret}"').replace(
        'method = "manual"', f'method = "{secret}"'
    )
    reg = load_register(make_register(tmp_path, {"broken": broken, "odd-key": odd}))
    assert reg.problems
    assert secret not in " ".join(reg.problems)


def test_files_that_do_not_belong_are_problems_not_skipped(tmp_path: Path) -> None:
    folder = make_register(tmp_path, {"a-key": key_text("a-key")})
    (folder / "notes.txt").write_text("hello")
    (folder / "huge.toml").write_text("#" * (MAX_FILE_BYTES + 1))
    (folder / "link.toml").symlink_to(folder / "a-key.toml")
    reg = load_register(folder)
    joined = " ".join(reg.problems)
    assert "only .toml key files" in joined
    assert "larger than" in joined
    assert "not a plain file" in joined
    assert "a-key" in reg.keys  # the good file is still read


def test_an_empty_missing_or_huge_folder_is_refused(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert any("no key files" in p for p in load_register(empty).problems)
    assert any("missing" in p for p in load_register(tmp_path / "nope").problems)
    many = tmp_path / "many"
    many.mkdir()
    for i in range(MAX_FILES + 1):
        (many / f"k{i:04}.toml").write_text("")
    assert any("more than" in p for p in load_register(many).problems)


def test_text_from_a_file_is_cut_to_printable_ascii() -> None:
    assert printable("a\x1b[31mred\nline‮") == "a?[31mred?line?"
    assert len(printable("x" * 500)) == 60
    key, problems = parse_key(
        "f.toml",
        "a-key",
        {
            "id": "a-key",
            "name": "n\x1b[2Jame",
            "vendor": "limacharlie",
            "method": "manual",
            "sensitive": False,
            "period_days": 90,
        },
    )
    assert problems == [] and key is not None and "\x1b" not in key.name


# ---- the apply details of an automatic key ----


def parsed(tmp_path: Path, text: str, sub: str = "apply") -> Register:
    return load(tmp_path, {"auto-key": text}, sub)


def test_a_supported_automatic_key_carries_everything_apply_needs(tmp_path: Path) -> None:
    reg = parsed(tmp_path, key_text("auto-key", method="automatic"))
    assert reg.problems == []
    spec = reg.keys["auto-key"].apply
    assert spec is not None and reg.keys["auto-key"].apply_note == ""
    assert (spec.console_name, spec.perms, spec.secret_name) == (
        "x",
        ("sensor.list", "dr.list"),
        "AUTO_KEY_VALUE",
    )
    assert (spec.env_file, spec.env_var, spec.restart) == ("env/auto.env", "AUTO_KEY", ("posture",))
    assert (spec.project, spec.path, spec.org_name, spec.grace_minutes) == (
        "SOC-rotated",
        "/SOC",
        "SOC_LC_OID",
        10,
    )
    assert spec.check == "posture_check"


@pytest.mark.parametrize(
    ("old", "new", "fragment"),
    [
        (
            'forbidden_perms = ["output.*", "apikey.*"]',
            'forbidden_perms = ["apikey.*"]',
            "must refuse output",
        ),
        (
            'forbidden_perms = ["output.*", "apikey.*"]',
            'forbidden_perms = ["output.*"]',
            "must refuse output",
        ),
        (
            'perms = ["sensor.list", "dr.list"]',
            'perms = ["sensor.list", "output.list"]',
            "forbidden list refuses",
        ),
        (
            'perms = ["sensor.list", "dr.list"]',
            'perms = ["sensor.list", "apikey.ctrl"]',
            "forbidden list refuses",
        ),
        ('perms = ["sensor.list", "dr.list"]', 'perms = ["Not A Perm"]', "not a permission"),
        ('perms = ["sensor.list", "dr.list"]', "perms = []", "empty for a key marked ready"),
    ],
)
def test_an_unsafe_permission_list_refuses_the_whole_register(
    tmp_path: Path, old: str, new: str, fragment: str
) -> None:
    reg = parsed(tmp_path, key_text("auto-key", method="automatic").replace(old, new))
    assert any(fragment in p for p in reg.problems), reg.problems
    assert reg.keys == {}


@pytest.mark.parametrize(
    ("old", "new", "why"),
    [
        ('check = "posture_check"', 'check = "reconcile_check"', "no such health check"),
        ('project = "SOC-rotated"', 'project = "SOC"', "not in project SOC-rotated"),
        ('kind = "secrets_manager"', 'kind = "nordpass"', "not in the secrets manager"),
        (
            'names = ["AUTO_KEY_VALUE"]',
            'names = ["AUTO_KEY_VALUE", "OTHER_VALUE"]',
            "one stored value",
        ),
        ('kind = "env_file"', 'kind = "github_actions_secret"', "env file on the host only"),
        ('env_file = "env/auto.env"', 'env_file = "../x"', "malformed"),
        ('org_store_name = "SOC_LC_OID"\n', "", "no org_store_name"),
    ],
)
def test_what_this_build_cannot_do_yet_is_skipped_with_a_reason_not_refused(
    tmp_path: Path, old: str, new: str, why: str
) -> None:
    reg = parsed(tmp_path, key_text("auto-key", method="automatic").replace(old, new))
    assert reg.problems == []
    key = reg.keys["auto-key"]
    assert key.apply is None and why in key.apply_note


def test_a_key_that_is_not_ready_or_not_a_detection_vendor_key_has_no_apply_details(
    tmp_path: Path,
) -> None:
    reg = parsed(tmp_path, key_text("auto-key", method="automatic", ready=False))
    assert reg.problems == [] and reg.keys["auto-key"].apply is None
    assert reg.keys["auto-key"].apply_note == "not ready"
    other = key_text("auto-key", method="automatic").replace(
        'vendor = "limacharlie"', 'vendor = "self"'
    )
    reg2 = parsed(tmp_path, other, "other")
    assert reg2.keys["auto-key"].apply is None
