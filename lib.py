import contextlib
import fcntl
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime

from yaml import YAMLError, safe_load

logger = logging.getLogger(__name__)


def find_executable(executable):
    """Find the absolute path of an executable

    :return: path
    :rtype: str
    :raises FileNotFoundError: if the executable is not on PATH
    """
    path = shutil.which(executable)
    if not path:
        raise FileNotFoundError(f"Failed to identify path of {executable}")
    return path


def get_inventory():
    """Fetch ansible-inventory --list

    :return: inventory
    :rtype: dict
    """
    inventory_cmd = find_executable("ansible-inventory")

    cache_file = os.environ.get("BASTION_ANSIBLE_INV_CACHE_FILE")
    cache_timeout = int(os.environ.get("BASTION_ANSIBLE_INV_CACHE_TIMEOUT", "60"))
    inventory_options = os.environ.get("BASTION_ANSIBLE_INV_OPTIONS", "")
    command = f"{inventory_cmd} {inventory_options} --list"

    if not cache_file:
        return get_inv_from_command(command)

    # return from cache without acquiring a lock if cache exists and is not expired
    cache = get_inventory_from_cache(cache_file=cache_file, cache_timeout=cache_timeout)
    if cache:
        return cache.get("inventory")

    # acquire an exclusive lock so only one process runs ansible-inventory
    lock_file = cache_file + ".lock"
    with open(lock_file, "w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            # Re-check cache after acquiring lock; another process may have populated it
            cache = get_inventory_from_cache(
                cache_file=cache_file, cache_timeout=cache_timeout
            )
            if cache:
                return cache.get("inventory")

            inventory = get_inv_from_command(command)
            write_inventory_to_cache(cache_file=cache_file, inventory=inventory)
            return inventory
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def get_inventory_from_cache(cache_file, cache_timeout):
    """Read ansible-inventory from cache file

    :return: Inventory cache with `updated_at` (to expire the cache) and
        `inventory` (results of `ansible-inventory` command) keys.
    :rtype: dict
    """
    try:
        # Load JSON from cache file
        with open(cache_file) as fd:
            cache = json.load(fd)
    except OSError:
        # File does not exist or path is incorrect
        return None
    except ValueError:
        # Invalid JSON, treat as expired
        cache = None

    # Check cache expiry
    if cache and cache.get("updated_at", 0) >= int(time.time()) - cache_timeout:
        return cache

    # Cache expired or invalid
    with contextlib.suppress(OSError):
        os.remove(cache_file)

    return None


def write_inventory_to_cache(cache_file, inventory):
    """Write inventory with last update time to a cache file"""
    cache = {"inventory": inventory, "updated_at": int(time.time())}
    with open(cache_file, "w") as fd:
        json.dump(cache, fd)


def get_hostvars(host) -> dict:
    """Fetch hostvars for the given host

    Ansible either uses the "ansible_host" inventory variable or the hostname.
    Fetch inventory and browse all hostvars to return only the ones for the host.

    :return: hostvars
    :rtype: dict
    """
    inventory = get_inventory()
    all_hostvars = inventory.get("_meta", {}).get("hostvars", {})
    for inventory_host, hostvars in all_hostvars.items():
        if inventory_host == host or hostvars.get("ansible_host") == host:
            return hostvars
    # Host not found
    return {}


def manage_conf_file(conf_file, bastion_host, bastion_port, bastion_user):
    """Fetch the bastion vars from a config file.

    There will be set if not already defined, and before looking in the ansible inventory

    """

    yaml_conf = load_conf_file(conf_file)
    if not bastion_host:
        bastion_host = yaml_conf.get("bastion_host")
    if not bastion_port:
        bastion_port = yaml_conf.get("bastion_port")
    if not bastion_user:
        bastion_user = yaml_conf.get("bastion_user")

    return bastion_host, bastion_port, bastion_user


def load_conf_file(conf_file):
    """Load the yaml config file, {} if missing or invalid"""
    if not os.path.exists(conf_file):
        return {}
    try:
        with open(conf_file) as f:
            return safe_load(f) or {}
    except (YAMLError, OSError) as e:
        print(f"Error loading yaml file: {e}")
        return {}


def get_var_within(my_value, hostvar, check_list=None):
    """If a value is a jinja2 var, try to resolve it in the hostvars

    Ex:
        "my_value" == {{ my_jinja2_var }}
        "my_jinja2_var" == "foo"

    Will return "foo" for "my_value"

    """
    # keep track of parsed values
    # we want to avoid:
    # bastion_host == {{ foo }}
    # foo == {{ bastion_host }}
    if check_list is None:
        check_list = []

    if (
        isinstance(my_value, str)
        and my_value.startswith("{{")
        and my_value.endswith("}}")
    ):
        # ex: {{ my_jinja2_var }} -> lookup for 'my_jinja2_var' in hostvars
        key_name = my_value.replace("{{", "").replace("}}", "").strip()

        if key_name not in check_list:
            check_list.append(key_name)
            # resolve intricated vars
            return get_var_within(
                hostvar.get(key_name, ""), hostvar, check_list=check_list
            )
        else:
            return ""

    return my_value


def get_inv_from_command(command):
    p = subprocess.Popen(
        command,
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output, error = p.communicate()
    if isinstance(output, bytes):
        output = output.decode()
    if not p.returncode:
        inventory = json.loads(output)
        return inventory
    else:
        logger.error(error)
        raise RuntimeError("failed to get inventory")


def awx_get_inventory_file():
    # awx execution environment run dir, where the project and inventory are copied
    default_run_dir = "/runner"
    run_dir = os.environ.get("AWX_RUN_DIR", default_run_dir)
    return f"{run_dir}/inventory/hosts"


def awx_get_vars(host_ip, inventory_file):
    # the inventory file is a script that print the inventory in json format
    inv = get_inv_from_command(inventory_file)

    # the ssh command sent only the IP to the ansible bastion wrapper.
    # We are looking for the host which "ansible_host" has the same ip, then try to fetch the required vars from
    # its host_vars
    host = None
    host_vars = {}
    for k, v in inv.get("_meta", {}).get("hostvars", {}).items():
        if v.get("ansible_host") == host_ip:
            host = k
            host_vars = v
            break

    # this should not happen
    if not host:
        return {}

    bastion_vars = get_bastion_vars(host_vars)

    if None not in [
        bastion_vars.get("bastion_host"),
        bastion_vars.get("bastion_port"),
        bastion_vars.get("bastion_user"),
    ]:
        return bastion_vars

    # if some bastion vars are missing, maybe they are defined as group_vars.
    # We do an inventory lookup to get them.
    # With AWX no need to list the whole inventory, we already know the host
    command = f"ansible-inventory -i {inventory_file} --host {host}"
    return get_inv_from_command(command)


def get_bastion_vars(host_vars):
    bastion_host = host_vars.get("bastion_host")
    bastion_user = host_vars.get("bastion_user")
    bastion_port = host_vars.get("bastion_port")
    return {
        "bastion_host": bastion_host,
        "bastion_port": bastion_port,
        "bastion_user": bastion_user,
    }


# --- SSH certificate renewal (OpenBao) ---------------------------------------

CERT_VARS = (
    "bastion_cert_public_key",
    "bastion_bao_sign_path",
    "bastion_bao_addr",
    "bastion_bao_token_file",
    "bastion_cert_ttl",
)
CERT_DEFAULTS = {"bastion_cert_ttl": "15m"}
# renew the certificate when it expires within this many seconds
CERT_RENEW_MARGIN = 300


def get_cert_config(cmd, conf_file, hostvar):
    """Resolve the bastion_cert_* / bastion_bao_* vars.

    Same precedence as the bastion vars: playbook environment (prefix of the
    ssh command), config file, inventory hostvars, OS environment.
    Returns {} when no public key is configured (feature disabled).
    """
    cmd_env = dict(
        tok.split("=", 1)
        for tok in cmd.split(" ")
        if tok.upper().startswith("BASTION_") and "=" in tok
    )
    conf = load_conf_file(conf_file)
    cfg = {}
    for name in CERT_VARS:
        value = (
            cmd_env.get(name.upper())
            or conf.get(name)
            or get_var_within(hostvar.get(name), hostvar)
            or os.environ.get(name.upper())
            or CERT_DEFAULTS.get(name)
        )
        if value:
            cfg[name] = value
    if "bastion_cert_public_key" not in cfg:
        return {}
    return cfg


def cert_expires_within(cert, seconds):
    """True if the certificate is missing, unreadable or expires within `seconds`"""
    p = subprocess.run(
        ["ssh-keygen", "-L", "-f", cert],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if p.returncode:
        return True
    m = re.search(r"Valid: .*(?:to|before) (\S+)", p.stdout.decode())
    if not m:
        return False  # "Valid: forever" or no end date
    # ssh-keygen prints local time
    expires = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").timestamp()
    return expires < time.time() + seconds


def sign_cert(cfg, public_key, cert):
    """Sign public_key with OpenBao and write the certificate to `cert`"""
    env = dict(os.environ)
    if cfg.get("bastion_bao_addr"):
        env["BAO_ADDR"] = cfg["bastion_bao_addr"]
    if cfg.get("bastion_bao_token_file"):
        with open(os.path.expanduser(cfg["bastion_bao_token_file"])) as f:
            env["BAO_TOKEN"] = f.read().strip()
    p = subprocess.run(
        [
            "bao",
            "write",
            "-field=signed_key",
            cfg["bastion_bao_sign_path"],
            "public_key=@" + public_key,
            "ttl=" + cfg["bastion_cert_ttl"],
        ],
        env=env,
        capture_output=True,
        check=False,
    )
    if p.returncode:
        raise RuntimeError(f"bao write failed: {p.stderr.decode().strip()}")
    tmp = cert + ".tmp"
    with open(tmp, "wb") as f:
        f.write(p.stdout)
    os.replace(tmp, cert)


def ensure_cert(cfg, bastion_host, bastion_user):
    """Renew the bastion certificate if needed, return the ssh args to use it.

    The certificate is stored per bastion user and host next to the private
    key, so the same key can be signed by different CAs / for different
    bastion accounts.
    """
    public_key = os.path.expanduser(cfg["bastion_cert_public_key"])
    key = public_key.removesuffix(".pub")
    cert = f"{key}-{bastion_user}@{bastion_host}-cert.pub"

    if cert_expires_within(cert, CERT_RENEW_MARGIN):
        # ansible forks several wrappers at once: only one of them should sign
        with open(cert + ".lock", "w") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                if cert_expires_within(cert, CERT_RENEW_MARGIN):
                    sign_cert(cfg, public_key, cert)
            except Exception as e:  # noqa: BLE001
                # not fatal: let ssh fail with the real authentication error
                print(
                    f"bastion wrapper: certificate renewal failed: {e}",
                    file=sys.stderr,
                )
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)

    return ["-i", key, "-o", "CertificateFile=" + cert]
