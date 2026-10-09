variable "account_id" {
  type = string
}

variable "widgets" {
  description = <<-EOT
    Contents of account/turnstile.yaml, keyed by a stable widget name.
      domains          list of hostnames this widget is valid on (a widget
                       can cover more than one domain)
      mode             managed | non-interactive | invisible
      bot_fight_mode    optional
  EOT
  type = map(object({
    domains        = list(string)
    mode           = string
    bot_fight_mode = optional(bool)
  }))
  default = {}

  validation {
    condition     = alltrue([for w in values(var.widgets) : contains(["managed", "non-interactive", "invisible"], w.mode)])
    error_message = "mode must be managed, non-interactive or invisible."
  }
}
