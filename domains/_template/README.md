# Domain template

Do not edit this folder for a real domain. Create one with:

    make new D=example.org ZONE_ID=<32-char zone id> PLAN=pro

or, for a zone that already exists in Cloudflare:

    make export D=example.org ZONE_ID=<zone id>

Every YAML file here is fully commented out, so a new domain changes
nothing until you uncomment something. Each file explains its own format.
See docs/ at the repo root for step-by-step guides.
