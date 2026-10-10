"""CLI argument definitions independent of command execution."""
import argparse
from config import PLANS
from workflow.terminal import TerminalParser


def subcmd(sub, name, fn, **kw):
    """Add a subparser wired to fn, with a domain/account positional unless root=False."""
    root = kw.pop("root", True)
    p = sub.add_parser(name, **kw)
    p.set_defaults(fn=fn)
    if root:
        p.add_argument("domain", help="a folder name under domains/, or 'account'")
    return p


def add_backend_arg(p):
    p.add_argument("--backend", choices=["local", "r2"], help="default: $CF_BACKEND, else r2")


def build_parser(handlers, description):
    ap = TerminalParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.command_guide = True
    sub = ap.add_subparsers(dest="command")

    sub.add_parser("help", help="show this message")

    subcmd(sub, "validate", handlers["cmd_validate"])
    subcmd(sub, "validate-all", handlers["cmd_validate_all"], root=False)

    add_backend_arg(subcmd(sub, "init", handlers["cmd_init"]))
    add_backend_arg(subcmd(sub, "plan", handlers["cmd_plan"]))

    p = subcmd(sub, "apply", handlers["cmd_apply"])
    p.add_argument("--yes", action="store_true")

    p = subcmd(sub, "deviation-check", handlers["cmd_deviation_check"])
    add_backend_arg(p)
    p.add_argument("--deviation-exit", action="store_true", help="exit 2 when deviation exists (else always exit 0)")

    p = subcmd(sub, "migrate", handlers["cmd_migrate"])
    p.add_argument("--to", choices=["local", "r2"])

    subcmd(sub, "test", handlers["cmd_test"])
    subcmd(sub, "test-all", handlers["cmd_test_all"], root=False)
    subcmd(sub, "unit", handlers["cmd_unit"], root=False)
    subcmd(sub, "fmt", handlers["cmd_fmt"], root=False)
    subcmd(sub, "lint", handlers["cmd_lint"], root=False)
    subcmd(sub, "domains", handlers["cmd_domains"], root=False)

    p = subcmd(sub, "new", handlers["cmd_new"], root=False)
    p.add_argument("domain", help="name of the new domain, e.g. example.org")
    p.add_argument("--zone-id", required=True)
    p.add_argument("--plan", required=True, choices=PLANS)

    p = subcmd(sub, "export", handlers["cmd_export"], root=False)
    p.add_argument("domain", help="domain to export into, e.g. example.org")
    p.add_argument("--zone-id", required=True)
    p.add_argument("--force", action="store_true")
    p.add_argument("--plan", choices=PLANS)

    p = subcmd(sub, "export-account", handlers["cmd_export_account"], root=False)
    p.add_argument("--account-id", required=True)
    p.add_argument("--plan", choices=PLANS)

    p = subcmd(sub, "changed-domains", handlers["cmd_changed_domains"], root=False)
    p.add_argument("base", nargs="?", default=None, help="git ref to diff against (default origin/main)")
    p.add_argument("--all", action="store_true")

    return ap
