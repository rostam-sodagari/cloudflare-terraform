"""Small, dependency-free presentation helpers for interactive terminals."""
import argparse
import os
import shutil
import sys
import textwrap


COMMAND_GROUPS = (
    ("Everyday", (
        ("validate", "Check domain or account YAML"),
        ("validate-all", "Check every configured root"),
        ("plan", "Review proposed Cloudflare changes"),
        ("apply", "Apply the saved, reviewed plan"),
        ("deviation-check", "Find changes made outside Git"),
    )),
    ("Setup and state", (
        ("new", "Create a domain from the template"),
        ("export", "Import live zone configuration into YAML"),
        ("export-account", "Import live account configuration into YAML"),
        ("init", "Initialize the Terraform backend"),
        ("migrate", "Move state between local storage and R2"),
    )),
    ("Maintenance", (
        ("test", "Run Terraform mock tests for one root"),
        ("test-all", "Run all root and module mock tests"),
        ("unit", "Run Python unit tests"),
        ("fmt", "Format Terraform files"),
        ("lint", "Check formatting and validate YAML"),
        ("domains", "List domain folders"),
        ("changed-domains", "Emit changed roots as JSON for CI"),
        ("help", "Show this command guide"),
    )),
)
GROUP_COLOURS = {"Everyday": "1;32", "Setup and state": "1;36", "Maintenance": "1;35"}


def interactive(stream=None):
    stream = sys.stdout if stream is None else stream
    return stream.isatty() and os.environ.get("TERM") != "dumb"


def colour(code, text, stream=None):
    stream = sys.stdout if stream is None else stream
    if interactive(stream) and "NO_COLOR" not in os.environ:
        return f"\033[{code}m{text}\033[0m"
    return text


def heading(command, target=None):
    if interactive():
        title = command.replace("-", " ").title()
        print("\n" + colour("1;36", f"Cloudflare / {title}"))
        if target:
            print("  Target: " + colour("1;33", target))
        print()


def step(message):
    if interactive():
        print(colour("1;36", "  > ") + colour(36, message), flush=True)


class TerminalParser(argparse.ArgumentParser):
    """Use a compact command guide on terminals; retain argparse output in logs."""

    def print_help(self, file=None):
        stream = sys.stdout if file is None else file
        if not interactive(stream):
            return super().print_help(file)
        if not getattr(self, "command_guide", False):
            for help_line in self.format_help().splitlines():
                if help_line.startswith("usage:") or help_line.endswith(":"):
                    help_line = colour("1;36", help_line, stream)
                elif help_line.lstrip().startswith("--") or help_line.startswith("  -"):
                    help_line = colour(33, help_line, stream)
                print(help_line, file=stream)
            return
        width = max(32, min(shutil.get_terminal_size().columns, 100))

        def line(text="", indent="", code=None, highlight=None):
            # Wrap plain text first so escape sequences do not affect alignment.
            parts = textwrap.wrap(text, width=width, initial_indent=indent,
                                  subsequent_indent=indent) or [""]
            for index, part in enumerate(parts):
                if highlight and index == 0:
                    part = part.replace(highlight, colour(code, highlight, stream), 1)
                elif code and not highlight:
                    part = colour(code, part, stream)
                print(part, file=stream)

        print(colour("1;36", "Cloudflare Terraform", stream), file=stream)
        line("Manage YAML configuration, review plans, and apply changes.")
        line()
        line(f"Usage: python {self.prog} <command> [arguments]", code="1;33")
        for group, commands in COMMAND_GROUPS:
            line()
            group_colour = GROUP_COLOURS[group]
            print(colour(group_colour, group, stream), file=stream)
            for name, description in commands:
                line(f"{name:<18} {description}", indent="  ", code=group_colour, highlight=name)
        line()
        print(colour("1;33", "Start here", stream), file=stream)
        for example in ("python cf.py validate example.com",
                        "python cf.py plan example.com",
                        "python cf.py apply example.com"):
            line(example, indent="  ", code=32)
        line()
        line("Use 'account' as the target for account configuration.")
        line("State defaults to R2. Use --backend local or CF_BACKEND=local for local state.")
        line("Set TF=tofu to use OpenTofu.")
        line("Run python cf.py <command> --help for arguments and options.")
