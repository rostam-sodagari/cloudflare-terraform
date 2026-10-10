"""Execute Python and Terraform with explicit executable dependencies."""
import subprocess
import sys


def run_py(script, args, capture=False, *, scripts_dir):
    kw = dict(capture_output=True, text=True) if capture else {}
    return subprocess.run([sys.executable, str(scripts_dir / script), *args], **kw)


def run_tf(args, capture=False, *, executable, fail):
    kw = dict(capture_output=True, text=True) if capture else {}
    try:
        return subprocess.run([executable, *args], **kw)
    except FileNotFoundError:
        fail(f"'{executable}' not found on PATH. Install Terraform "
             "(https://developer.hashicorp.com/terraform/install), or set executable=tofu to use OpenTofu.")
