"""Export Cloudflare and R2 credentials from Delinea Secret Server to a GitHub job."""
import os
import re
import sys
import uuid

FIELDS = {"CLOUDFLARE_API_TOKEN": "cloudflare-api-token",
          "AWS_ACCESS_KEY_ID": "r2-access-key-id",
          "AWS_SECRET_ACCESS_KEY": "r2-secret-access-key",
          "R2_ACCOUNT_ID": "r2-account-id",
          "TF_VAR_notification_webhook_secrets": "notification-webhook-secrets",
          "TF_VAR_logpush_destinations": "logpush-destinations",
          "FRESHSERVICE_API_KEY": "freshservice-api-key"}


def values(secret):
    return {item["slug"]: item.get("itemValue") for item in secret.get("items", [])}


def export(output, name, value):
    # GitHub masks only secrets.*, never values fetched at runtime. A random
    # delimiter stops a newline in a value defining further variables.
    for line in value.splitlines():
        print(f"::add-mask::{line}")
    delimiter = f"__DELINEA_{uuid.uuid4().hex}__"
    output.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")


def approver_token(server, folder, logins, unavailable):
    """Return the latest approver's token; there is no shared token to fall back to."""
    for login in reversed(logins):
        if not re.fullmatch(r"[A-Za-z0-9-]+", login):
            raise RuntimeError(f"Invalid GitHub login: {login}")
        path = "\\".join((folder.rstrip("\\/"), login, "cloudflare-token"))
        try:
            token = values(server.get_secret_by_path(path, fetch_file_attachments=False)).get("cloudflare-api-token")
        except unavailable:
            continue
        if token:
            return login, token
    raise RuntimeError(f"No approver has a readable Cloudflare token under {folder}: {', '.join(logins)}")


def connect(url, username, password, domain):
    from delinea.secrets.server import (DomainPasswordGrantAuthorizer, PasswordGrantAuthorizer,
                                        SecretServer, SecretServerClientError)
    authorizer = (DomainPasswordGrantAuthorizer(url, username, domain, password) if domain
                  else PasswordGrantAuthorizer(url, username, password))
    return SecretServer(url, authorizer), SecretServerClientError


def main():
    server, unavailable = connect(os.environ["TSS_SERVER_URL"], os.environ["TSS_USERNAME"],
                                  os.environ["TSS_PASSWORD"], os.environ.get("TSS_DOMAIN"))
    shared = values(server.get_secret(int(os.environ["TSS_SECRET_ID"]), fetch_file_attachments=False))
    logins = os.environ.get("APPROVERS", "").split()
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as output:
        # Missing fields stay quiet: the caller's "Check credentials" reports them once.
        for name, field in FIELDS.items():
            if shared.get(field):
                export(output, name, shared[field])
        if logins:
            login, token = approver_token(server, os.environ["TSS_APPROVER_FOLDER"], logins, unavailable)
            export(output, "CLOUDFLARE_API_TOKEN", token)
            print(f"::notice::Applying with {login}'s Cloudflare token.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # A failed fetch stops the job; SDK errors have no shared base here.
        print(f"::error::Delinea: {type(error).__name__}: {getattr(error, 'message', error)}")
        sys.exit(1)
