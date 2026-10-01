# 8. Local backend (state on your machine)

By default state is stored in **R2** and shared by everyone. The **local**
backend keeps it in `.state/` at the repo root instead. Use it for:

1. Trying the repo out before the R2 bucket exists.
2. A personal sandbox zone nobody else touches.
3. Working without R2 access (Cloudflare's API is still needed for plans).

Do **not** use it for shared zones: other people and CI cannot see your
state, so they would plan to create everything again. CI always uses R2
and refuses a local backend.

## Choosing the backend

| How | macOS / Linux | Windows |
|-----|---------------|---------|
| One command | `make plan D=example.com BACKEND=local` | `.\cf.ps1 plan example.com -Backend local` |
| Whole terminal session | `export CF_BACKEND=local` | `$env:CF_BACKEND = 'local'` |
| Back to R2 | omit it, or `BACKEND=r2` | omit it, or `-Backend r2` |

The choice is per root (a domain or `account`). `backend.hcl` and the R2
keys are not needed for local roots.

## Where the state goes

Same layout as the R2 keys:

```
.state/
├── account.tfstate
└── domains/
    ├── example.com.tfstate
    └── example.net.tfstate
```

`.state/` is git-ignored. **Never commit state.** It holds record contents,
rule expressions and resource IDs; in a public repo that publishes the
zone's configuration.

Back it up yourself (a synced folder or an encrypted archive). Nothing
else keeps a copy.

## How it works

`make` and `cf.ps1` write a git-ignored `backend_override.tf` into the root
for local runs, which replaces the R2 backend. For R2 runs the file is
removed. `providers.tf` never changes.

## Moving a root between backends

Terraform will not switch backends silently. If you change backend for a
root that already has state, `init` stops with *Backend configuration
changed* and points you to migrate:

```bash
make migrate D=example.com TO=r2        # local to R2
make migrate D=example.com TO=local     # R2 to local
```

```powershell
.\cf.ps1 migrate example.com -To r2
.\cf.ps1 migrate example.com -To local
```

Terraform asks before copying; answer `yes`. Then run a plan on the new
backend: it must say **No changes**. Once you are happy, delete the old
copy (the `.state/...` file, or the object in the R2 bucket) so there is
only one source of truth.

Typical path: build a zone locally, then `migrate ... TO=r2` before anyone
else works on it.

## Locking

The local backend locks the state file on disk, which only protects
against two runs on the same machine. That is another reason shared zones
belong in R2.
