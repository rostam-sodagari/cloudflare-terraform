variable "notification_webhook_secrets" {
  description = "Signing secrets and credential-bearing webhook URLs supplied through TF_VAR_notification_webhook_secrets, keyed by YAML secret_ref or url_ref."
  type        = map(string)
  sensitive   = true
  default     = {}
}

variable "logpush_destinations" {
  description = "Vault destinations supplied through TF_VAR_logpush_destinations, keyed by destination_conf_ref."
  type        = map(string)
  sensitive   = true
  default     = {}
}
