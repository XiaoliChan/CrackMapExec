def proto_args(parser, std_parser, module_parser):
    ssh_parser = parser.add_parser("ssh", help="own stuff using SSH", parents=[std_parser, module_parser])
    ssh_parser.add_argument("--key-file", type=str, help="Authenticate using the specified private key. Treats the password parameter as the key's passphrase.")
    ssh_parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    ssh_parser.add_argument("--ssh-timeout", help="SSH connection timeout, default is %(default)s secondes", type=int, default=15)
    ssh_parser.add_argument("--sudo-check", action="store_true", help="Check user privilege with sudo")
    ssh_parser.add_argument("--sudo-check-method", choices={"sudo-stdin", "mkfifo"}, default="sudo-stdin", help="method to do with sudo check, default is '%(default)s (mkfifo is non-stable, probably you need to execute once again if it failed)'")
    ssh_parser.add_argument("--get-output-tries", help="Number of times with sudo command tries to get results, default is %(default)s", type=int, default=5)

    cgroup = ssh_parser.add_argument_group("Command Execution", "Options for executing commands")
    cgroup.add_argument("--no-output", action="store_true", help="do not retrieve command output")
    cgroup.add_argument("-x", metavar="COMMAND", dest="execute", help="execute the specified command")

    return parser