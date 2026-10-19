import os

from yaml import dump

from lib import (
    awx_get_inventory_file,
    get_bastion_vars,
    get_var_within,
    manage_conf_file,
)

BASTION_HOST = "my_bastion"
BASTION_PORT = 22
BASTION_USER = "my_bastion_user"
BASTION_CONF_FILE = "/tmp/test_bastion_conf_file.yml"


def test_manage_conf_file_bastion_host_undefined():
    bastion_host, bastion_port, bastion_user = manage_conf_file(
        BASTION_CONF_FILE, None, BASTION_PORT, BASTION_USER
    )
    assert bastion_host == BASTION_HOST


def test_manage_conf_file_bastion_port_undefined():
    bastion_host, bastion_port, bastion_user = manage_conf_file(
        BASTION_CONF_FILE, BASTION_HOST, None, BASTION_USER
    )
    assert bastion_port == BASTION_PORT


def test_manage_conf_file_bastion_user_undefined():
    bastion_host, bastion_port, bastion_user = manage_conf_file(
        BASTION_CONF_FILE, BASTION_HOST, BASTION_PORT, None
    )
    assert bastion_user == BASTION_USER


def test_manage_conf_file_bastion_all_undefined():
    write_conf_file(BASTION_CONF_FILE)
    bastion_host, bastion_port, bastion_user = manage_conf_file(
        BASTION_CONF_FILE, None, None, None
    )
    assert bastion_user == BASTION_USER
    assert bastion_port == BASTION_PORT
    assert bastion_host == BASTION_HOST


def write_conf_file(conf_file):
    with open(conf_file, "w") as f:

        data = {
            "bastion_host": BASTION_HOST,
            "bastion_port": BASTION_PORT,
            "bastion_user": BASTION_USER,
        }

        dump(data, f)


write_conf_file(BASTION_CONF_FILE)


def test_get_var_within_one_level():
    hostvars = {"bastion_host": "{{ bastion_fqdn }}", "bastion_fqdn": "my_real_bastion"}
    bastion_host = get_var_within(hostvars["bastion_host"], hostvars)
    assert bastion_host == hostvars["bastion_fqdn"]


def test_get_var_within_two_levels():
    hostvars = {
        "bastion_host": "{{ bastion_fqdn }}",
        "bastion_fqdn": "{{ my_other_var }}",
        "my_other_var": "my_real_bastion",
    }
    bastion_host = get_var_within(hostvars["bastion_host"], hostvars)
    assert bastion_host == hostvars["my_other_var"]


def test_get_var_within_not_found():
    hostvars = {"bastion_host": "{{ bastion_fqdn }}"}
    bastion_host = get_var_within(hostvars["bastion_host"], hostvars)
    assert not bastion_host


def test_get_var_within_infinite():
    hostvars = {
        "bastion_host": "{{ bastion_fqdn }}",
        "bastion_fqdn": "{{ bastion_host }}",
    }
    bastion_host = get_var_within(hostvars["bastion_host"], hostvars)
    assert not bastion_host


def test_get_var_not_a_jinja2_var():
    hostvars = {"bastion_host": "{{ bastion_fqdn"}
    bastion_host = get_var_within(hostvars["bastion_host"], hostvars)
    assert bastion_host == hostvars["bastion_host"]


def test_get_var_not_a_string():
    hostvars = {"bastion_host": 68}
    bastion_host = get_var_within(hostvars["bastion_host"], hostvars)
    assert bastion_host == hostvars["bastion_host"]


def test_awx_get_inventory_file_default():
    assert awx_get_inventory_file() == "/runner/inventory/hosts"


def test_awx_get_inventory_file_env_defined():
    env_path = "/my_awx"
    os.environ["AWX_RUN_DIR"] = env_path
    assert awx_get_inventory_file() == f"{env_path}/inventory/hosts"
    os.environ.pop("AWX_RUN_DIR")


def test_get_bastion_vars():
    host_vars = {
        "bastion_port": BASTION_PORT,
        "bastion_host": BASTION_HOST,
        "bastion_user": BASTION_USER,
    }
    bastion_vars = get_bastion_vars(host_vars)
    assert (
        bastion_vars["bastion_port"] == BASTION_PORT
        and bastion_vars["bastion_host"] == BASTION_HOST
        and bastion_vars["bastion_user"] == BASTION_USER
    )


def test_get_bastion_vars_not_full():
    host_vars = {"bastion_port": BASTION_PORT, "bastion_user": BASTION_USER}
    bastion_vars = get_bastion_vars(host_vars)
    assert not bastion_vars["bastion_host"]


# --- SSH certificate renewal -------------------------------------------------

import subprocess

import pytest

from lib import cert_expires_within, ensure_cert, get_cert_config


@pytest.fixture
def keypair(tmp_path):
    """A user key and a CA, plus a helper to sign the key with a given validity."""
    ca = tmp_path / "ca"
    key = tmp_path / "id_test"
    for k in (ca, key):
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(k)], check=True
        )

    def sign(validity, cert):
        subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-s",
                str(ca),
                "-I",
                "t",
                "-V",
                validity,
                str(key) + ".pub",
            ],
            check=True,
            stderr=subprocess.DEVNULL,
        )
        os.replace(str(key) + "-cert.pub", cert)

    return key, sign


def test_cert_expires_within_valid(keypair, tmp_path):
    key, sign = keypair
    cert = str(tmp_path / "c")
    sign("+60m", cert)
    assert not cert_expires_within(cert, 300)


def test_cert_expires_within_soon(keypair, tmp_path):
    key, sign = keypair
    cert = str(tmp_path / "c")
    sign("+2m", cert)
    assert cert_expires_within(cert, 300)


def test_cert_expires_within_expired(keypair, tmp_path):
    key, sign = keypair
    cert = str(tmp_path / "c")
    sign("-2h:-1h", cert)
    assert cert_expires_within(cert, 300)


def test_cert_expires_within_missing(tmp_path):
    assert cert_expires_within(str(tmp_path / "nope"), 300)


def test_get_cert_config_precedence(tmp_path, monkeypatch):
    conf = tmp_path / "conf.yml"
    conf.write_text(
        "bastion_cert_public_key: conf.pub\nbastion_bao_sign_path: conf/sign\n"
    )
    monkeypatch.setenv("BASTION_BAO_SIGN_PATH", "env/sign")
    monkeypatch.setenv("BASTION_BAO_ADDR", "http://env")
    monkeypatch.setenv("BASTION_BAO_TOKEN_FILE", "env.token")
    hostvar = {
        "bastion_bao_addr": "{{ my_bao }}",
        "my_bao": "http://inv",
        "bastion_bao_token_file": "inv.token",
    }
    cmd = "BASTION_CERT_PUBLIC_KEY=cmd.pub /usr/bin/python3 && sleep 0"
    cfg = get_cert_config(cmd, str(conf), hostvar)
    assert cfg["bastion_cert_public_key"] == "cmd.pub"  # playbook env
    assert cfg["bastion_bao_sign_path"] == "conf/sign"  # config file
    assert cfg["bastion_bao_addr"] == "http://inv"  # inventory, jinja resolved
    assert cfg["bastion_bao_token_file"] == "inv.token"  # inventory over OS env
    assert cfg["bastion_cert_ttl"] == "15m"  # default


def test_get_cert_config_unset(tmp_path):
    assert get_cert_config("", str(tmp_path / "nope.yml"), {}) == {}


@pytest.fixture
def fake_bao(tmp_path, monkeypatch):
    """A `bao` on PATH that records its args/env and prints a canned signed key."""
    log = tmp_path / "bao.log"
    script = tmp_path / "bin" / "bao"
    script.parent.mkdir()
    script.write_text(
        "#!/bin/sh\n"
        'echo "$* ADDR=$BAO_ADDR TOKEN=$BAO_TOKEN" >> {}\n'
        '[ -n "$FAKE_BAO_FAIL" ] && exit 1\n'
        "echo signed-key-content\n".format(log)
    )
    script.chmod(0o755)
    monkeypatch.setenv("PATH", str(script.parent) + os.pathsep + os.environ["PATH"])
    return log


def test_ensure_cert_signs_and_returns_ssh_args(keypair, fake_bao, tmp_path):
    key, _ = keypair
    (tmp_path / "t").write_text("s.token\n")
    cfg = {
        "bastion_cert_public_key": str(key) + ".pub",
        "bastion_bao_sign_path": "ssh/sign/role",
        "bastion_bao_addr": "http://bao",
        "bastion_bao_token_file": str(tmp_path / "t"),
        "bastion_cert_ttl": "30m",
    }
    args = ensure_cert(cfg, "bastion1", "alice")
    cert = str(key) + "-alice@bastion1-cert.pub"
    assert args == ["-i", str(key), "-o", "CertificateFile=" + cert]
    assert open(cert).read().strip() == "signed-key-content"
    assert fake_bao.read_text().strip() == (
        "write -field=signed_key ssh/sign/role public_key=@{}.pub ttl=30m ADDR=http://bao TOKEN=s.token".format(
            key
        )
    )


def test_ensure_cert_keeps_valid_cert(keypair, fake_bao):
    key, sign = keypair
    cert = str(key) + "-alice@bastion1-cert.pub"
    sign("+60m", cert)
    before = open(cert).read()
    ensure_cert(
        {
            "bastion_cert_public_key": str(key) + ".pub",
            "bastion_bao_sign_path": "p",
            "bastion_cert_ttl": "60m",
        },
        "bastion1",
        "alice",
    )
    assert open(cert).read() == before
    assert not fake_bao.exists()


def test_ensure_cert_bao_failure_is_not_fatal(keypair, fake_bao, monkeypatch):
    key, _ = keypair
    monkeypatch.setenv("FAKE_BAO_FAIL", "1")
    args = ensure_cert(
        {
            "bastion_cert_public_key": str(key) + ".pub",
            "bastion_bao_sign_path": "p",
            "bastion_cert_ttl": "60m",
        },
        "b",
        "alice",
    )
    assert args[0] == "-i"
    assert not os.path.exists(str(key) + "-alice@b-cert.pub")
