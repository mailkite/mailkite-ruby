# MailKite examples — Ruby

Runnable, copy-pasteable examples. Each file's header comment lists what to set and `gem install`.

| File | What it shows |
| --- | --- |
| [`01_send_email.rb`](01_send_email.rb) | Send an email over a verified domain |
| [`02_receive_webhook.rb`](02_receive_webhook.rb) | Receive inbound mail as a webhook and **verify the HMAC signature** |
| [`03_agent_email_reply.rb`](03_agent_email_reply.rb) | **AI email agent** — inbound email → Claude drafts a reply → MailKite sends it, threaded |
| [`04_give_your_agent_an_inbox.rb`](04_give_your_agent_an_inbox.rb) | Give your agent its own address with MailKite's **built-in inbox agent** (no server) |
| [`05_server_login.rb`](05_server_login.rb) | **Server-side login + register** — your own account, or your users' accounts via OAuth |

Full docs: <https://mailkite.dev/docs> · AI agents: <https://mailkite.dev/docs/ai-agents>
