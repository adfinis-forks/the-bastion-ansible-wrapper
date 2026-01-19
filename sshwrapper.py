#!/usr/bin/env python3

import getpass
import os
import sys

from lib import (
    awx_get_inventory_file,
    awx_get_vars,
    find_executable,
    get_hostvars,
    get_var_within,
    get_totp_from_callback,
    manage_conf_file,
)


def main():
    argv = list(sys.argv[1:])  # Copy

    bastion_user = None
    bastion_host = None
    bastion_port = None
    totp_callback_command = None
    remote_user = None
    remote_port = 22
    default_configuration_file = "/etc/ovh/bastion/config.yml"

    cmd = argv.pop()
    host = argv.pop()

    # check if bastion_vars are passed as env vars in the playbook
    # may be usefull if the ansible controller manage many bastions
    # example :
    # - hosts: all
    #   gather_facts: false
    #   environment:
    #     BASTION_USER: "{{ bastion_user }}"
    #     BASTION_HOST: "{{ bastion_host }}"
    #     BASTION_PORT: "{{ bastion_port }}"
    #
    # will result as : ... '/bin/sh -c '"'"'BASTION_USER=my_bastion_user BASTION_HOST=my_bastion_host BASTION_PORT=22 /usr/bin/python3 && sleep 0'"'"''
    for i in list(cmd.split(" ")):
        if "bastion_user" in i.lower():
            bastion_user = i.split("=")[1]
        elif "bastion_host" in i.lower():
            bastion_host = i.split("=")[1]
        elif "bastion_port" in i.lower():
            bastion_port = i.split("=")[1]

    # Check for TOTP callback command in environment
    totp_callback_command = os.environ.get("BASTION_TOTP_CALLBACK")

    # in some cases (AWX in a non containerised environment for instance), the environment is overridden by the job
    # so we are not able to get the BASTION vars
    # if some vars are still undefined, try to load them from a configuration file
    if not bastion_host or not bastion_port or not bastion_user:
        bastion_host, bastion_port, bastion_user, totp_callback_command = (
            manage_conf_file(
                os.environ.get("BASTION_CONF_FILE", default_configuration_file),
                bastion_host,
                bastion_port,
                bastion_user,
                totp_callback_command,
            )
        )

    # lookup on the inventory may take some time, depending on the source, so use it only if not defined elsewhere
    # it seems like some module like template does not send env vars too...
    if not bastion_host or not bastion_port or not bastion_user:
        # check if running on AWX, we'll get the vars in a different way
        awx_inventory_file = awx_get_inventory_file()
        if os.path.exists(awx_inventory_file):
            hostvar = awx_get_vars(host, awx_inventory_file)
        else:
            hostvar = get_hostvars(host)  # dict

        # manage the case where a bastion var is defined from another var
        # Ex: bastion_host = {{ my_bastion_host }}
        bastion_port = get_var_within(
            hostvar.get("bastion_port", os.environ.get("BASTION_PORT", 22)), hostvar
        )
        bastion_user = get_var_within(
            hostvar.get(
                "bastion_user", os.environ.get("BASTION_USER", getpass.getuser())
            ),
            hostvar,
        )
        bastion_host = get_var_within(
            hostvar.get("bastion_host", os.environ.get("BASTION_HOST")), hostvar
        )

        # Get TOTP callback command from hostvar if not already set
        if not totp_callback_command:
            totp_callback_command = get_var_within(
                hostvar.get(
                    "totp_callback_command", os.environ.get("BASTION_TOTP_CALLBACK")
                ),
                hostvar,
            )

    for i, e in enumerate(argv):
        if e.startswith("User="):
            remote_user = e.split("=")[-1]
            argv[i] = "User={}".format(bastion_user)
        elif e.startswith("Port="):
            remote_port = e.split("=")[-1]
            argv[i] = "Port={}".format(bastion_port)

    # Build SSH command args
    args = (
        [
            "ssh",
            "-p",
            bastion_port,
            "-q",
            "-o",
            "StrictHostKeyChecking=no",
            "-l",
            bastion_user,
            bastion_host,
            "-T",
        ]
        + argv
        + [
            "--",
            "-q",
            "-T",
            "--never-escape",
            "--user",
            remote_user,
            "--port",
            remote_port,
            host,
            "--",
            cmd,
        ]
    )

    if totp_callback_command:
        control_path = None
        for i, arg in enumerate(argv):
            if arg.startswith("ControlPath="):
                control_path = arg.split("=", 1)[1].strip('"')
                break

        # skip TOTP handling if we have an existing ControlMaster connection
        use_pexpect = True
        if control_path and os.path.exists(control_path):
            use_pexpect = False

        if use_pexpect:
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
                        # Use interact() to hand over control back to Ansible
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

            except pexpect.exceptions.EOF as e:
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
    else:
        os.execv(
            find_executable("ssh"),  # full path mandatory
            [str(e).strip() for e in args],  # execv() arg 2 must contain only strings
        )


if __name__ == "__main__":
    main()
