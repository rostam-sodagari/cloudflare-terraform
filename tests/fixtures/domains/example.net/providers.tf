terraform {
  required_version = ">= 1.10"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.26"
    }
  }

  # R2 (S3-compatible). Settings come from ../../backend.hcl plus a
  # per-domain key; see cf.py's `init`/`plan` commands.
  backend "s3" {}
}

# Token is read from CLOUDFLARE_API_TOKEN (injected from Delinea in CI).
provider "cloudflare" {}
