#!/usr/bin/env python3

import getpass
import os
import sys

from lib import (
    control_opts,
    ensure_cert,
    find_executable,
    get_cert_config,
    get_hostvars,
    get_var_within,
    manage_conf_file,
)


def main():
    argv = list(sys.argv[1:])

    bastion_user = None
    bastion_host = None
    bastion_port = None
    remote_user = None
    remote_port = 22
    default_configuration_file = "/etc/ovh/bastion/config.yml"
    hostvar = {}

    ssh_opts = []

    iteration = enumerate(argv)
    for i, e in iteration:
        if e == "-o" and argv[i + 1].startswith("User="):
            remote_user = argv[i + 1].split("=")[-1]
            next(iteration)
        elif e == "-o" and argv[i + 1].startswith("Port="):
            remote_port = argv[i + 1].split("=")[-1]
            next(iteration)
        elif e == "-i" or (e == "-o" and argv[i + 1].startswith("UserKnownHostsFile=")):
            ssh_opts += [e, argv[i + 1]]
            next(iteration)

    argv.pop()  # sftp command, unused
    host = argv.pop()

    # Playbook environment variables are not pushed to the sftp wrapper
    # Skipping this source of configuration

    # Read from configuration file
    bastion_host, bastion_port, bastion_user = manage_conf_file(
        os.getenv("BASTION_CONF_FILE", default_configuration_file),
        bastion_host,
        bastion_port,
        bastion_user,
    )

    # Read from inventory and environment variables
    if not bastion_host or not bastion_port or not bastion_user:
        hostvar = get_hostvars(host)
        # resolve bastion_user: "{{ bastion_username }}" like sshwrapper does
        bastion_port = get_var_within(
            hostvar.get("bastion_port", os.getenv("BASTION_PORT", "22")), hostvar
        )
        bastion_user = get_var_within(
            hostvar.get("bastion_user", os.getenv("BASTION_USER", getpass.getuser())),
            hostvar,
        )
        bastion_host = get_var_within(
            hostvar.get("bastion_host", os.getenv("BASTION_HOST")), hostvar
        )

    if not remote_user:
        remote_user = bastion_user

    # one control socket per target host, shared with the ssh/scp wrappers
    ssh_opts = control_opts(
        ssh_opts,
        host,
        remote_port,
        remote_user,
        bastion_user,
        bastion_host,
        bastion_port,
    )

    # short lived ssh certificate signed by OpenBao, renewed when about to expire
    cert_cfg = get_cert_config(
        "", os.getenv("BASTION_CONF_FILE", default_configuration_file), hostvar
    )
    if cert_cfg:
        ssh_opts += ensure_cert(cert_cfg, bastion_host, bastion_user)

    args = (
        [
            "ssh",
            f"{bastion_user}@{bastion_host}",
            "-p",
            bastion_port,
            "-o",
            "StrictHostKeyChecking=no",
            "-T",
        ]
        + ssh_opts
        + [
            "--",
            "--user",
            remote_user,
            "--port",
            remote_port,
            "--host",
            host,
            "--osh",
            "sftp",
        ]
    )

    os.execv(
        find_executable("ssh"),
        [str(e).strip() for e in args],
    )


if __name__ == "__main__":
    main()
