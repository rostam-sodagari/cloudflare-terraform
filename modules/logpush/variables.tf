variable "account_id" {
  type = string
}

variable "jobs" {
  description = <<-EOT
    Contents of account/settings/logpush.yaml, keyed by a stable job name.
      dataset              e.g. audit_logs, http_requests, firewall_events
      destination_conf     e.g. s3://bucket/path?region=us-east-1
      enabled              optional, default true
      filter, frequency, logpull_options, ownership_challenge   optional
    ownership_challenge is the token from Cloudflare's one-time destination
    verification -- fetch it yourself (Cloudflare writes a challenge file
    to the destination) and paste it here; this module does not run that
    dance for you.
  EOT
  type = map(object({
    dataset              = string
    destination_conf     = optional(string)
    destination_conf_ref = optional(string)
    enabled              = optional(bool, true)
    filter               = optional(string)
    frequency            = optional(string)
    logpull_options      = optional(string)
    ownership_challenge  = optional(string)
  }))
  default = {}
}

variable "destinations" {
  type      = map(string)
  sensitive = true
  default   = {}
}
