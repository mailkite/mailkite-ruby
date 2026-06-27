# MailKite for Ruby

Official [MailKite](https://mailkite.dev) SDK. One low-level `request` plus one
method per endpoint. Zero dependencies — standard library only. Ruby 2.5+.

## Install

```bash
gem install mailkite
```

## Usage

```ruby
require "mailkite"

mk = Mailkite::Client.new(ENV["MAILKITE_API_KEY"])

res = mk.send(
  "from" => "hello@myapp.ai",
  "to" => "ada@example.com",
  "subject" => "Your invoice #1042",
  "html" => "<p>Thanks! Receipt attached.</p>"
)
```

Point at a different base URL with `Mailkite::Client.new(key, "https://api.mailkite.dev")`.

## Methods

`send(message)`, `agent(message)`, `route(message)`, `listDomains`, `createDomain(body)`, `getDomain(id)`,
`deleteDomain(id)`, `verifyDomain(id)`, `setWebhook(id, body)`,
`deleteWebhook(id)`, `testWebhook(id)`, `checkDomainAvailability(domain)`,
`registerDomain(body)`, `listRoutes`, `createRoute(body)`,
`listMessages`, `getMessage(id)`, `retryDelivery(id)`.

## Errors

```ruby
begin
  mk.send(msg)
rescue Mailkite::Error => e
  warn "#{e.status} #{e.message}"
end
```

See the [full docs](https://mailkite.dev/docs/libraries).
