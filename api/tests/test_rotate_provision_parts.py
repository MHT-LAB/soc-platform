"""First creation of a key, the parts: reading the register, the plan, the env file, the secrets
manager, the generator, the rules service's login check and the command line. The run itself,
with undo, is in test_rotate_provision.py."""

import json
import os
import stat
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from rotate_support import COMMIT, key_text, make_register
from test_rotate_clients import TOKEN, manager
from test_rotate_consumer import COMPOSE, FakeRun

from soc_api import rules_deploy
from soc_api.reconcile import LcError
from soc_api.rotate import cli
from soc_api.rotate import state as st
from soc_api.rotate.consumer import HostConsumer
from soc_api.rotate.keys import GENERATED_CHARSET, load_register
from soc_api.rotate.net import RotateError
from soc_api.rotate.plan import build_plan, render
from soc_api.rotate.provision import generate
from soc_api.rotate.rights import Secret

TODAY = date(2026, 11, 18)
VALUE = "FIRSTVALUE-aaaaaaaaaaaaaaaaaaaa"


def vendor_toml(
    key_id: str = "rules-key", *, ready: bool = False, consumer: str | None = None
) -> str:
    consumer = (
        consumer
        if consumer is not None
        else (
            '[[consumer]]\nkind = "env_file"\nhost = "ct110"\nenv_file = "env/rules-lc.env"\n'
            'restart = []\ncheck = "rules_plan"\n\n[consumer.env_map]\n'
            'RULES_KEY = "SOC_RULES_LC_KEY"\n'
        )
    )
    return (
        f'id = "{key_id}"\nname = "Rules key"\nvendor = "limacharlie"\nmethod = "automatic"\n'
        f"sensitive = true\nperiod_days = 30\nready = {str(ready).lower()}\n"
        'console_name = "rules-key"\npurpose = "x"\n\n'
        '[scope]\nperms = ["dr.list", "dr.set"]\nforbidden_perms = ["output.*", "apikey.*"]\n'
        'org_store_name = "SOC_LC_OID"\n\n'
        '[store]\nkind = "secrets_manager"\nproject = "SOC-rotated"\npath = "/SOC"\n'
        'names = ["RULES_KEY"]\n\n' + consumer
    )


def self_toml(key_id: str = "stamp-key", *, generate_block: str | None = None) -> str:
    block = (
        generate_block
        if generate_block is not None
        else f'[generate]\nkind = "random"\nlength = 48\ncharset = "{GENERATED_CHARSET}"\n'
    )
    return (
        f'id = "{key_id}"\nname = "STAMP"\nvendor = "self"\nmethod = "automatic"\n'
        'sensitive = false\nperiod_days = 90\nready = false\nconsole_name = "none"\n'
        'purpose = "x"\n\n' + block + '\n[store]\nkind = "secrets_manager"\n'
        'project = "SOC-rotated"\npath = "/SOC"\nnames = ["STAMP_KEY"]\n\n'
        '[[consumer]]\nkind = "env_file"\nhost = "ct110"\nenv_file = "env/rules-lc.env"\n'
        'restart = []\ncheck = "none"\n\n[consumer.env_map]\nSTAMP_KEY = "SOC_RULES_STAMP_KEY"\n\n'
        '[[consumer]]\nkind = "env_file"\nhost = "ct110"\nenv_file = "env/posture-rules.env"\n'
        'restart = ["posture"]\ncheck = "posture_check"\n\n[consumer.env_map]\n'
        'STAMP_KEY = "SOC_POSTURE_STAMP_KEY"\n'
    )


def spec_of(tmp_path: Path, text: str, key_id: str = "rules-key") -> Any:
    reg = load_register(make_register(tmp_path, {key_id: text}))
    assert reg.problems == [], reg.problems
    return reg.keys[key_id].provision


# ---- reading the register ----


def test_a_not_ready_vendor_key_with_a_full_spec_can_be_created(tmp_path: Path) -> None:
    spec = spec_of(tmp_path, vendor_toml())
    assert spec is not None
    assert (spec.vendor, spec.console_name, spec.perms) == (
        "limacharlie",
        "rules-key",
        ("dr.list", "dr.set"),
    )
    assert (spec.org_name, spec.path, spec.secret_name, spec.length) == (
        "SOC_LC_OID",
        "/SOC",
        "RULES_KEY",
        0,
    )
    [c] = spec.consumers
    assert (c.env_file, c.env_var, c.restart, c.check) == (
        "env/rules-lc.env",
        "SOC_RULES_LC_KEY",
        (),
        "rules_plan",
    )


def test_a_self_key_needs_a_random_value_and_may_have_two_files(tmp_path: Path) -> None:
    spec = spec_of(tmp_path, self_toml(), "stamp-key")
    assert spec is not None and spec.vendor == "self" and spec.length == 48
    assert spec.perms == () and spec.console_name == "" and spec.org_name == ""
    assert [c.env_file for c in spec.consumers] == ["env/rules-lc.env", "env/posture-rules.env"]
    assert [c.check for c in spec.consumers] == ["none", "posture_check"]


@pytest.mark.parametrize(
    "block",
    [
        "",  # no generate table at all
        '[generate]\nkind = "random"\nlength = 31\ncharset = "A-Za-z0-9._-"\n',
        '[generate]\nkind = "random"\nlength = 129\ncharset = "A-Za-z0-9._-"\n',
        '[generate]\nkind = "random"\nlength = true\ncharset = "A-Za-z0-9._-"\n',
        '[generate]\nkind = "random"\nlength = "48"\ncharset = "A-Za-z0-9._-"\n',
        '[generate]\nkind = "random"\nlength = 48\ncharset = "A-Za-z0-9._-+"\n',
        '[generate]\nkind = "words"\nlength = 48\ncharset = "A-Za-z0-9._-"\n',
    ],
)
def test_a_self_key_with_a_wrong_generate_table_is_not_creatable(
    tmp_path: Path, block: str
) -> None:
    assert spec_of(tmp_path, self_toml(generate_block=block), "stamp-key") is None


def test_a_ready_key_is_rotated_never_created(tmp_path: Path) -> None:
    assert spec_of(tmp_path, vendor_toml(ready=True)) is None


@pytest.mark.parametrize(
    "consumer",
    [
        # a service that is restarted but never checked
        '[[consumer]]\nkind = "env_file"\nhost = "ct110"\nenv_file = "env/a.env"\n'
        'restart = ["posture"]\ncheck = "none"\n\n[consumer.env_map]\nRULES_KEY = "A_B"\n',
        # a check no one built
        '[[consumer]]\nkind = "env_file"\nhost = "ct110"\nenv_file = "env/a.env"\n'
        'restart = []\ncheck = "rules_restamp"\n\n[consumer.env_map]\nRULES_KEY = "A_B"\n',
        # a follow-up step, another host, another kind
        '[[consumer]]\nkind = "env_file"\nhost = "ct110"\nenv_file = "env/a.env"\n'
        'restart = []\ncheck = "none"\npost_step = "x"\n\n[consumer.env_map]\nRULES_KEY = "A_B"\n',
        '[[consumer]]\nkind = "env_file"\nhost = "other"\nenv_file = "env/a.env"\n'
        'restart = []\ncheck = "none"\n\n[consumer.env_map]\nRULES_KEY = "A_B"\n',
        '[[consumer]]\nkind = "k8s"\nhost = "ct110"\nenv_file = "env/a.env"\n'
        'restart = []\ncheck = "none"\n\n[consumer.env_map]\nRULES_KEY = "A_B"\n',
        # a path that climbs out of env/, and a map of the wrong name
        '[[consumer]]\nkind = "env_file"\nhost = "ct110"\nenv_file = "env/../x.env"\n'
        'restart = []\ncheck = "none"\n\n[consumer.env_map]\nRULES_KEY = "A_B"\n',
        '[[consumer]]\nkind = "env_file"\nhost = "ct110"\nenv_file = "env/a.env"\n'
        'restart = []\ncheck = "none"\n\n[consumer.env_map]\nOTHER = "A_B"\n',
        "",  # no consumer
    ],
)
def test_a_consumer_this_build_cannot_serve_makes_the_key_not_creatable(
    tmp_path: Path, consumer: str
) -> None:
    assert spec_of(tmp_path, vendor_toml(consumer=consumer)) is None


def test_a_file_nothing_restarts_may_still_name_a_real_check(tmp_path: Path) -> None:
    for check in ("posture_check", "rules_plan", "none"):
        consumer = (
            '[[consumer]]\nkind = "env_file"\nhost = "ct110"\nenv_file = "env/a.env"\n'
            f'restart = []\ncheck = "{check}"\n\n[consumer.env_map]\nRULES_KEY = "A_B"\n'
        )
        sub = tmp_path / check
        sub.mkdir()
        assert spec_of(sub, vendor_toml(consumer=consumer)) is not None, check


def test_two_consumers_may_not_name_the_same_file(tmp_path: Path) -> None:
    text = self_toml().replace("env/posture-rules.env", "env/rules-lc.env")
    assert spec_of(tmp_path, text, "stamp-key") is None


def test_the_scope_rules_still_apply_to_a_key_that_does_not_exist_yet(tmp_path: Path) -> None:
    bad = vendor_toml().replace('"dr.set"]', '"output.list"]')
    reg = load_register(make_register(tmp_path, {"rules-key": bad}))
    assert reg.problems and "rules-key" not in reg.keys  # refused, as for any key file


# ---- the plan ----


def plan_for(tmp_path: Path, files: dict[str, str], state: st.State | None = None) -> Any:
    reg = load_register(make_register(tmp_path, files))
    assert reg.problems == []
    return build_plan(reg, state or st.State(), TODAY, COMMIT)


def test_the_plan_lists_a_random_key_before_a_vendor_key(tmp_path: Path) -> None:
    plan = plan_for(tmp_path, {"rules-key": vendor_toml(), "stamp-key": self_toml()})
    assert [r.key.id for r in plan.provisions] == ["stamp-key", "rules-key"]
    assert plan.counts["to_create"] == 2
    lines = "\n".join(render(plan))
    assert "Keys to create for the first time (2):" in lines
    assert "a random value; goes to env/rules-lc.env, env/posture-rules.env" in lines
    assert "a vendor key, 2 permission(s); goes to env/rules-lc.env" in lines


def test_a_key_that_was_ever_made_or_attempted_is_not_listed_again(tmp_path: Path) -> None:
    for outcome in ("provisioned", "failed"):
        state = st.State(keys={"rules-key": st.KeyState(TODAY, outcome)})
        sub = tmp_path / outcome
        sub.mkdir()
        plan = plan_for(sub, {"rules-key": vendor_toml()}, state)
        assert plan.provisions == () and plan.counts["to_create"] == 0


def test_the_plan_hash_covers_what_is_to_be_created(tmp_path: Path) -> None:
    (a := tmp_path / "a").mkdir()
    (b := tmp_path / "b").mkdir()
    one = plan_for(a, {"rules-key": vendor_toml()})
    two = plan_for(b, {"rules-key": vendor_toml(), "stamp-key": self_toml()})
    assert one.plan_hash != two.plan_hash  # approving one list is not approving the other


def test_a_plan_with_nothing_to_create_hashes_as_it_did_before(tmp_path: Path) -> None:
    import hashlib

    plan = plan_for(tmp_path, {"manual-key": key_text("manual-key")})  # nothing automatic
    payload = json.dumps({"commit": COMMIT, "actions": []}, separators=(",", ":"))
    assert plan.provisions == ()
    assert plan.plan_hash == hashlib.sha256(payload.encode()).hexdigest()[:12]


# ---- the env file ----


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / "env").mkdir()
    return tmp_path


def consumer(root: Path, run: FakeRun | None = None) -> HostConsumer:
    return HostConsumer(root, COMPOSE, run=run or FakeRun(), environ={})


def test_a_missing_file_is_created_with_only_the_one_line_and_mode_600(root: Path) -> None:
    created = consumer(root).add("env/new.env", "SOC_X", Secret(VALUE))
    path = root / "env" / "new.env"
    assert created is True and path.read_text() == f"SOC_X={VALUE}\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert [p.name for p in (root / "env").iterdir()] == ["new.env"]  # no stray temp file


def test_an_existing_file_gets_the_line_appended_and_the_rest_is_kept(root: Path) -> None:
    path = root / "env" / "a.env"
    path.write_text('ORG=acme\nPREFIXES="T - |BASE - "')  # no trailing newline, a quote kept
    path.chmod(0o640)
    created = consumer(root).add("env/a.env", "SOC_X", Secret(VALUE))
    assert created is False
    assert path.read_text() == f'ORG=acme\nPREFIXES="T - |BASE - "\nSOC_X={VALUE}\n'
    assert stat.S_IMODE(path.stat().st_mode) == 0o640  # the mode the person set
    assert (root / "env" / "a.env.prev").read_text() == 'ORG=acme\nPREFIXES="T - |BASE - "'


def test_a_variable_that_is_already_there_is_never_replaced(root: Path) -> None:
    path = root / "env" / "a.env"
    path.write_text("SOC_X=old\n")
    c = consumer(root)
    assert c.has_var("env/a.env", "SOC_X") is True
    with pytest.raises(RotateError) as err:
        c.add("env/a.env", "SOC_X", Secret(VALUE))
    assert err.value.code == "env_var_present"
    assert path.read_text() == "SOC_X=old\n" and not (root / "env" / "a.env.prev").exists()


def test_has_var_is_false_for_a_missing_file_and_matches_whole_names_only(root: Path) -> None:
    c = consumer(root)
    assert c.has_var("env/none.env", "SOC_X") is False
    (root / "env" / "a.env").write_text("SOC_XY=1\n#SOC_X=2\n")
    assert c.has_var("env/a.env", "SOC_X") is False  # SOC_XY= and a comment are not SOC_X=


def test_a_leftover_prev_file_stops_an_append(root: Path) -> None:
    (root / "env" / "a.env").write_text("A=1\n")
    (root / "env" / "a.env.prev").write_text("left over")
    with pytest.raises(RotateError) as err:
        consumer(root).add("env/a.env", "SOC_X", Secret(VALUE))
    assert err.value.code == "prev_exists"
    assert (root / "env" / "a.env").read_text() == "A=1\n"


def test_undo_deletes_a_file_it_made_and_restores_one_it_extended(root: Path) -> None:
    c = consumer(root)
    c.add("env/new.env", "SOC_X", Secret(VALUE))
    c.remove("env/new.env", True)
    assert not (root / "env" / "new.env").exists()
    (root / "env" / "a.env").write_text("A=1\n")
    c.add("env/a.env", "SOC_X", Secret(VALUE))
    c.remove("env/a.env", False)
    assert (root / "env" / "a.env").read_text() == "A=1\n"
    assert not (root / "env" / "a.env.prev").exists()


@pytest.mark.parametrize(
    ("env_file", "var", "value"),
    [
        ("env/new.env", "lower", VALUE),
        ("env/new.env", "SOC_X", "short"),
        ("env/new.env", "SOC_X", "has space in it aaaaaaaa"),
        ("../etc/x.env", "SOC_X", VALUE),
        ("env/NEW.env", "SOC_X", VALUE),
    ],
)
def test_a_bad_name_or_value_writes_nothing(
    root: Path, env_file: str, var: str, value: str
) -> None:
    with pytest.raises(RotateError):
        consumer(root).add(env_file, var, Secret(value))
    assert list((root / "env").iterdir()) == []


def test_the_rules_check_runs_the_rules_service_in_its_check_mode(root: Path) -> None:
    run = FakeRun(0)
    assert consumer(root, run).check("rules_plan") is True
    argv, kw = run.calls[0]
    assert argv[1:] == [
        "run",
        "--rm",
        "-T",
        "rules",
        "python",
        "-m",
        "soc_api.rules_deploy",
        "check",
    ]
    assert kw["stdin"] is not None  # no standard input: the rights came in on it
    assert FakeRun(1) and consumer(root, FakeRun(1)).check("rules_plan") is False


# ---- the secrets manager ----


def test_create_posts_the_value_in_the_body_and_never_in_the_url() -> None:
    client, fake = manager({})
    client.create("/SOC", "STAMP_KEY", Secret(VALUE))
    call = fake.calls[1]
    assert call["method"] == "POST" and call["url"].endswith("/api/v3/secrets/raw/STAMP_KEY")
    body = json.loads(call["data"])
    assert body["secretValue"] == VALUE and body["secretPath"] == "/SOC"
    assert VALUE not in call["url"] and VALUE not in str(call.get("headers"))


def test_delete_names_the_one_secret_by_path_and_project_only() -> None:
    client, fake = manager({})
    client.delete("/SOC", "STAMP_KEY")
    call = fake.calls[1]
    assert call["method"] == "DELETE" and call["url"].endswith("/api/v3/secrets/raw/STAMP_KEY")
    assert json.loads(call["data"]) == {
        "workspaceId": "proj-12345678",
        "environment": "dev",
        "secretPath": "/SOC",
    }
    assert call["headers"]["Authorization"] == f"Bearer {TOKEN}"


def test_exists_is_no_only_for_a_not_found_and_an_error_for_anything_else() -> None:
    client, _ = manager({"secret": {"secretValue": VALUE}})
    assert client.exists("/SOC", "STAMP_KEY") is True
    client, _ = manager(RotateError("http_404"))
    assert client.exists("/SOC", "STAMP_KEY") is False
    for code in ("http_403", "http_500", "timeout"):
        client, _ = manager(RotateError(code))
        with pytest.raises(RotateError):
            client.exists("/SOC", "STAMP_KEY")


@pytest.mark.parametrize("call", ["create", "delete"])
def test_a_bad_secret_name_is_refused_before_any_call(call: str) -> None:
    client, fake = manager()
    args: tuple[Any, ...] = ("/SOC", "../x") + ((Secret(VALUE),) if call == "create" else ())
    with pytest.raises(RotateError) as err:
        getattr(client, call)(*args)
    assert err.value.code.endswith("bad_name") and len(fake.calls) == 0


# ---- the generator ----


def test_a_generated_value_has_the_right_length_charset_and_a_safe_first_character() -> None:
    seen = {generate(48).reveal() for _ in range(200)}
    assert len(seen) == 200  # never the same twice
    for value in seen:
        assert len(value) == 48 and value[0].isalnum()
        assert all(c.isalnum() or c in "._-" for c in value)


@pytest.mark.parametrize(
    ("length", "charset"), [(15, GENERATED_CHARSET), (256, GENERATED_CHARSET), (48, "a-z")]
)
def test_a_generator_asked_for_anything_odd_refuses(length: int, charset: str) -> None:
    with pytest.raises(RotateError):
        generate(length, charset)


def test_a_generated_value_cannot_be_printed() -> None:
    value = generate(48)
    assert str(value) == "***" and repr(value) == "Secret(***)" and f"{value}" == "***"


# ---- the rules service's login check ----


class ListsRules:
    def __init__(self, rules: dict[str, Any] | Exception) -> None:
        self.rules = rules

    def list_rules(self) -> dict[str, Any]:
        if isinstance(self.rules, Exception):
            raise self.rules
        return self.rules


ENV = {
    "SOC_RULES_LC_KEY": "RULESKEY-aaaaaaaaaaaaaaaa",
    "SOC_RULES_LC_OID": "01234567-89ab-cdef-0123-456789abcdef",
}


def test_the_rules_check_lists_and_says_a_count_never_a_name() -> None:
    said: list[str] = []
    code = rules_deploy.check(ENV, said.append, lambda _o, _k: ListsRules({"SECRET RULE NAME": 1}))
    assert code == rules_deploy.OK
    assert said == ["check ok: signed in and listed 1 rule(s); nothing was changed"]
    assert "SECRET" not in " ".join(said) and ENV["SOC_RULES_LC_KEY"] not in " ".join(said)


def test_the_rules_check_fails_when_it_cannot_sign_in() -> None:
    said: list[str] = []
    code = rules_deploy.check(ENV, said.append, lambda _o, _k: ListsRules(LcError("http_401")))
    assert code == rules_deploy.FAILED and "could not sign in" in said[0]
    assert said[0].endswith("(http_401)")  # the step's code, so a failure says which part


@pytest.mark.parametrize("drop", ["SOC_RULES_LC_KEY", "SOC_RULES_LC_OID"])
def test_the_rules_check_needs_only_the_key_and_the_organization(drop: str) -> None:
    said: list[str] = []
    calls: list[str] = []
    code = rules_deploy.check(
        {k: v for k, v in ENV.items() if k != drop},
        said.append,
        lambda *_: calls.append("x"),  # type: ignore[arg-type,return-value]
    )
    assert code == rules_deploy.REFUSED and calls == []
    # and with just those two it works: no commit, rules folder or stamp key is asked for
    assert (
        rules_deploy.check(ENV, lambda _l: None, lambda _o, _k: ListsRules({})) == rules_deploy.OK
    )


def test_the_rules_service_runs_check_mode_only_for_the_exact_word(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(rules_deploy, "check", lambda _env: 42)
    assert rules_deploy.main(["check"]) == 42
    monkeypatch.setattr(
        rules_deploy.Config,
        "from_env",
        staticmethod(lambda _e: (_ for _ in ()).throw(rules_deploy.ConfigError("x"))),
    )
    assert (
        rules_deploy.main(["check", "extra"]) == rules_deploy.REFUSED
    )  # not check mode: a normal run


# ---- the command line ----


def test_provision_takes_exactly_one_plan_hash() -> None:
    args = cli.parse_args(["--provision", "0123456789ab"])
    assert (args.mode, args.plan_hash) == ("provision", "0123456789ab")
    for bad in (
        ["--provision"],
        ["--provision", "abc"],
        ["--provision", "0123456789AB"],
        ["--provision", "0123456789ab", "x"],
        ["--provision", "$(id)"],
    ):
        with pytest.raises(cli.UsageError):
            cli.parse_args(bad)


def test_the_container_never_runs_provision(tmp_path: Path) -> None:
    said: list[str] = []
    cfg = cli.Config(tmp_path, tmp_path, COMMIT)
    code = cli.run(
        cfg, cli.Args("provision", plan_hash="0123456789ab"), lambda _p: True, said.append
    )
    assert code == cli.REFUSED and "runs on the host" in said[0]


def test_provision_is_a_host_mode_in_main(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []
    monkeypatch.setattr(cli, "_host_run", lambda _cfg, args: seen.append(args.mode) or 0)
    monkeypatch.setenv("SOC_ROTATE_COMMIT", COMMIT)
    assert cli.main(["--provision", "0123456789ab"]) == 0 and seen == ["provision"]
    assert os.environ["SOC_ROTATE_COMMIT"] == COMMIT


def test_a_file_that_does_not_hold_the_new_line_after_the_write_is_not_trusted(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (root / "env" / "a.env").write_text("A=1\n")
    c = consumer(root)
    answers = iter([False, False])  # not there before; still not there when read back
    monkeypatch.setattr(HostConsumer, "has_var", lambda *_a: next(answers))
    with pytest.raises(RotateError) as err:
        c.add("env/a.env", "SOC_X", Secret(VALUE))
    assert err.value.code == "env_readback_failed"
    # and the file is exactly as it was, with no copy left: the caller never saw it touched
    assert (root / "env" / "a.env").read_text() == "A=1\n"
    assert not (root / "env" / "a.env.prev").exists()


# ---- approving a plan that only creates keys ----


def test_a_plan_with_only_keys_to_create_can_be_approved(tmp_path: Path) -> None:
    keys = make_register(tmp_path, {"rules-key": vendor_toml()})
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    said: list[str] = []
    cfg = cli.Config(keys, state_dir, COMMIT)
    code = cli.run(cfg, cli.Args("approve"), lambda _prompt: True, said.append)
    assert code == cli.OK
    state = st.load(state_dir / "state.json")
    assert state.approval is not None
    plan = build_plan(load_register(keys), state, TODAY, COMMIT)
    assert plan.provisions and state.approval.plan_hash == plan.plan_hash
    text = "\n".join(said)
    assert "Keys to create for the first time (1):" in text
    assert "nothing to approve" not in text and "rotate.sh --provision" in text
    assert f"PLAN HASH (copy this): {plan.plan_hash}" in said
    assert f"  rotate.sh --provision {plan.plan_hash}" in said
    assert f"  rotate.sh --apply {plan.plan_hash}" not in said
