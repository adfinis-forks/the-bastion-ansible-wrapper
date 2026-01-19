#!/usr/bin/env python3

import getpass
import os
import sys

from lib import (
    find_executable,
    get_hostvars,
    get_totp_from_callback,
    manage_conf_file,
)


def main():
    argv = list(sys.argv[1:])

    bastion_user = None
    bastion_host = None
    bastion_port = None
    totp_callback_command = None
    remote_user = None
    remote_port = 22
    default_configuration_file = "/etc/ovh/bastion/config.yml"

    iteration = enumerate(argv)
    for i, e in iteration:
        if e == "-o" and argv[i + 1].startswith("User="):
            remote_user = argv[i + 1].split("=")[-1]
            next(iteration)
        elif e == "-o" and argv[i + 1].startswith("Port="):
            remote_port = argv[i + 1].split("=")[-1]
            next(iteration)

    sftpcmd = argv.pop()
    host = argv.pop()

    # Playbook environment variables are not pushed to the sftp wrapper
    # Skipping this source of configuration

    # Read from configuration file
    bastion_host, bastion_port, bastion_user, totp_callback_command = manage_conf_file(
        os.getenv("BASTION_CONF_FILE", default_configuration_file),
        bastion_host,
        bastion_port,
        bastion_user,
        os.environ.get("BASTION_TOTP_CALLBACK"),
    )

    # Read from inventory and environment variables
    if not bastion_host or not bastion_port or not bastion_user:
        inventory = get_hostvars(host)
        bastion_port = inventory.get("bastion_port", os.getenv("BASTION_PORT", 22))
        bastion_user = inventory.get(
            "bastion_user", os.getenv("BASTION_USER", getpass.getuser())
        )
        bastion_host = inventory.get("bastion_host", os.getenv("BASTION_HOST"))
        if not totp_callback_command:
            totp_callback_command = inventory.get(
                "totp_callback_command", os.getenv("BASTION_TOTP_CALLBACK")
            )

    args = [
        "ssh",
        "{}@{}".format(bastion_user, bastion_host),
        "-p",
        bastion_port,
        "-o",
        "StrictHostKeyChecking=no",
        "-T",
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

    if totp_callback_command:
        try:
            import pexpect
        except ImportError:
            print(
                "Error: pexpect module is required for TOTP support. Install it with: pip install pexpect",
                file=sys.stderr,
            )
            sys.exit(1)

        child = pexpect.spawn(
            find_executable("ssh"),
            [str(e).strip() for e in args][1:],
            echo=False,
        )

        try:
            index = child.expect(
                [
                    r"(?i)(verification code)",
                    pexpect.EOF,
                    pexpect.TIMEOUT,
                ],
                timeout=30,
            )

            if index == 0:  # TOTP prompt
                totp = get_totp_from_callback(totp_callback_command)
                if totp:
                    child.sendline(totp)
                    child.interact()
                    child.close()
                    exit_status = (
                        child.exitstatus if child.exitstatus is not None else 0
                    )
                    sys.exit(exit_status)
                else:
                    print(
                        "\nError: Failed to get TOTP code from callback command",
                        file=sys.stderr,
                    )
                    child.close()
                    sys.exit(1)
            elif index == 1:  # EOF
                child.interact()
            else:  # Timeout
                child.close()
                sys.exit(1)

            child.close()
            exit_status = child.exitstatus if child.exitstatus is not None else 0
            sys.exit(exit_status)

        except pexpect.exceptions.EOF:
            child.close()
            sys.exit(child.exitstatus if child.exitstatus is not None else 1)

        except Exception:
            child.close()
            sys.exit(1)
    else:
        os.execv(
            find_executable("ssh"),
            [str(e).strip() for e in args],
        )


if __name__ == "__main__":
    main()
