"""Reporting helpers for configuration validation."""
import os
import sys
from yamlio import line_for
from .paths import ROOT


class Report:
    def __init__(self):
        self.items = []

    def add(self, level, file, line, msg, hint=None):
        self.items.append((level, str(file), line or 1, msg, hint))

    @property
    def errors(self):
        return [i for i in self.items if i[0] == "error"]

    def print(self):
        gha = os.environ.get("GITHUB_ACTIONS") == "true"
        for level, file, line, msg, hint in self.items:
            rel = os.path.relpath(file, ROOT) if os.path.isabs(file) else file
            rel = rel.replace(os.sep, "/")
            full = msg + (f" Fix: {hint}" if hint else "")
            if gha:
                print(f"::{level} file={rel},line={line}::{full}")
            colour = "\033[31m" if level == "error" else "\033[33m"
            reset = "\033[0m" if sys.stdout.isatty() else ""
            colour = colour if sys.stdout.isatty() else ""
            print(f"{colour}{level.upper()}{reset} {rel}:{line}: {msg}")
            if hint:
                print(f"    fix: {hint}")

class Ctx:
    """File-scoped helper so checks can say ctx.error(path, msg)."""

    def __init__(self, report, file, lines, plan, gate=None):
        self.r, self.file, self.lines, self.plan = report, file, lines, plan
        self.gate = gate

    def error(self, path, msg, hint=None):
        self.r.add("error", self.file, line_for(self.lines, path), msg, hint)

    def warn(self, path, msg, hint=None):
        self.r.add("warning", self.file, line_for(self.lines, path), msg, hint)

    def flag(self, check_id, path, msg, hint=None):
        """Like warn(), but the severity (or whether it fires at all) is
        controlled by policy.yaml -- see validation/policy.py. Used for
        best-practice checks, as opposed to error()/warn() which are for
        structural correctness and always fire."""
        gate = self.gate
        if gate is None:
            from .policy import GATE
            gate = GATE
        severity = gate.severity(check_id)
        if severity is None:
            return
        (self.error if severity == "error" else self.warn)(path, msg, hint)
