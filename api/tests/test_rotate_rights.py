"""The rights reader (soc_api.rotate.rights): standard input only, and never an echo of a value."""

import copy
import io
import pickle
from typing import Any

import pytest

from soc_api.rotate.rights import (
    MAX_LINE_CHARS,
    Rights,
    RightsError,
    Secret,
    read_rights,
)

KEY = "LCROTATORKEY-aaaaaaaaaaaaaaaa"
CID = "CLIENTID-0123456789"
CSEC = "CLIENTSECRET-aaaaaaaaaaaaaaaa"
GOOD = (
    f"LC_ROTATOR_KEY={KEY}\n"
    f"SECRETS_CLIENT_ID={CID}\n"
    f"SECRETS_CLIENT_SECRET={CSEC}\n"
    "SECRETS_URL=https://secrets.example.test\n"
    "SECRETS_PROJECT_ID=projectid-aaaaaaaa\n"
)


class Pipe(io.StringIO):
    """Standard input as a pipe: not a terminal."""


class Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_the_four_required_fields_are_read_and_the_environment_defaults() -> None:
    r = read_rights(Pipe(GOOD + "\n"))
    assert (r.lc_key.reveal(), r.client_id.reveal(), r.client_secret.reveal()) == (KEY, CID, CSEC)
    assert r.project_id.startswith("projectid") and r.environment == "dev"
    assert r.secrets_url == "https://secrets.example.test"


def test_the_environment_can_be_given() -> None:
    r = read_rights(Pipe(GOOD + "SECRETS_ENVIRONMENT=prod\n\n"))
    assert r.environment == "prod"


def test_reading_stops_at_the_blank_line_and_takes_nothing_after_it() -> None:
    stream = Pipe(GOOD + "\nANYTHING AFTER THE BLANK LINE\n")
    read_rights(stream)
    assert stream.read() == "ANYTHING AFTER THE BLANK LINE\n"


def test_end_of_input_without_a_blank_line_is_fine() -> None:
    assert read_rights(Pipe(GOOD)).lc_key.reveal() == KEY


def test_a_terminal_is_refused_so_rights_are_never_typed() -> None:
    with pytest.raises(RightsError, match="pipe"):
        read_rights(Terminal(GOOD))


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("", "missing LC_ROTATOR_KEY"),
        (GOOD.replace("SECRETS_PROJECT_ID", "NOT_A_FIELD"), "unknown field NOT_A_FIELD"),
        (GOOD + f"LC_ROTATOR_KEY={KEY}\n", "LC_ROTATOR_KEY is given twice"),
        (GOOD.replace(KEY, "short"), "LC_ROTATOR_KEY is not in the expected form"),
        (GOOD.replace(KEY, KEY + " extra"), "LC_ROTATOR_KEY is not in the expected form"),
        (GOOD + "no equals sign here\n", "unknown field"),
        (
            GOOD + "SECRETS_ENVIRONMENT=Prod!\n",
            "SECRETS_ENVIRONMENT is not in the expected form",
        ),
        (GOOD.split("\n", 1)[1], "missing LC_ROTATOR_KEY"),
    ],
)
def test_each_wrong_input_is_named_by_field(text: str, fragment: str) -> None:
    with pytest.raises(RightsError, match=fragment):
        read_rights(Pipe(text))


def test_a_sixth_line_and_a_line_that_is_too_long_are_refused() -> None:
    with pytest.raises(RightsError, match="unknown field"):
        read_rights(Pipe(GOOD + "SECRETS_ENVIRONMENT=dev\nEXTRA=1\nEXTRA=2\nEXTRA=3\n"))
    with pytest.raises(RightsError, match="too long"):
        read_rights(Pipe("LC_ROTATOR_KEY=" + "a" * (MAX_LINE_CHARS + 10) + "\n"))


def test_no_error_ever_echoes_what_was_typed() -> None:
    secret = "VALUE-that-must-never-be-printed-9f8e7d6c5b4a"
    inputs = [
        f"LC_ROTATOR_KEY={secret} with a space\n",
        f"{secret}\n",
        f"{secret}={secret}\n",
        GOOD + f"UNKNOWN={secret}\n",
        GOOD + f"LC_ROTATOR_KEY={secret}\n",
    ]
    for text in inputs:
        with pytest.raises(RightsError) as exc:
            read_rights(Pipe(text))
        assert secret not in str(exc.value)


def test_a_secret_cannot_be_printed_formatted_copied_or_saved() -> None:
    s = Secret(KEY)
    assert (
        KEY not in repr(s) and KEY not in str(s) and KEY not in f"{s}" and KEY not in f"{s!r:>40}"
    )
    assert s.reveal() == KEY
    rights = read_rights(Pipe(GOOD))
    for text in (repr(rights), str(rights), f"{rights}"):
        assert KEY not in text and CSEC not in text and CID not in text
    with pytest.raises(TypeError):
        pickle.dumps(s)
    with pytest.raises(TypeError):
        copy.copy(s)


def test_a_secret_in_a_log_call_or_exception_message_stays_hidden() -> None:
    s = Secret(KEY)
    holder: Any = {"k": s, "r": [s]}
    assert KEY not in str(holder) and KEY not in repr(holder)
    assert isinstance(read_rights(Pipe(GOOD)), Rights)


@pytest.mark.parametrize(
    "url",
    [
        "http://secrets.example.test",
        "https://secrets.example.test/path",
        "https://secrets.example.test:8443",
        "https://user:pw" + chr(64) + "secrets.example.test",  # credentials in the URL
        "https://Secrets.Example.Test",
        "https://a",
        "secrets.example.test",
        "https://secrets.example.test?x=1",
    ],
)
def test_the_service_address_must_be_https_and_a_host_name_only(url: str) -> None:
    with pytest.raises(RightsError, match="SECRETS_URL is not in the expected form"):
        read_rights(Pipe(GOOD.replace("https://secrets.example.test", url)))
