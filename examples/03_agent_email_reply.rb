# An AI email agent: inbound email → Claude drafts a reply → MailKite sends it, threaded.
# Give your product an inbox that answers itself.
#
# Flow: MailKite POSTs the inbound `email.received` event → verify it → Claude composes a concise
# reply → send it back with `inReplyTo` so it threads to the sender.
#
# Run:  MAILKITE_API_KEY=mk_live_… MAILKITE_WEBHOOK_SECRET=whsec_… ANTHROPIC_API_KEY=sk-ant-… \
#       ruby 03_agent_email_reply.rb   # serves on :3000
# Deps: gem install mailkite sinatra anthropic

require "json"
require "sinatra"
require "mailkite"
require "anthropic"

mk = Mailkite::Client.new(ENV.fetch("MAILKITE_API_KEY"))
claude = Anthropic::Client.new  # reads ANTHROPIC_API_KEY
SECRET = ENV.fetch("MAILKITE_WEBHOOK_SECRET")

SYSTEM = "You are the support agent for Acme. Read the customer's email and write a short, friendly " \
         "reply that directly answers them. Plain text. If you can't help, say a human will follow up."

set :port, 3000

post "/hooks/mailkite" do
  raw = request.body.read  # verify against the RAW body — re-serialized JSON breaks the HMAC
  signature = request.env["HTTP_X_MAILKITE_SIGNATURE"]
  halt 401, "bad signature" unless mk.verifyWebhook(signature, raw, SECRET)

  event = JSON.parse(raw)
  halt 200, Mailkite.reply_ok unless event["type"] == "email.received"
  m = event["message"] || event  # { from, to, subject, text, html, messageId, … }

  # 1. Claude drafts the reply.
  msg = claude.messages.create(
    model: :"claude-opus-4-8",  # swap to claude-sonnet-4-6 / claude-haiku-4-5 for lower cost
    max_tokens: 1024,
    system_: SYSTEM,
    messages: [{ role: "user", content: "From: #{m['from']}\nSubject: #{m['subject']}\n\n#{m['text'] || m['html']}" }]
  )
  reply = msg.content.find { |b| b.type == :text }&.text || "Thanks — a human will follow up."

  # 2. Send it back, threaded to the original.
  subject = m["subject"].to_s.start_with?("Re:") ? m["subject"] : "Re: #{m['subject']}"
  mk.send(
    "from" => m["to"],  # reply from the address that received the mail
    "to" => m["from"],
    "subject" => subject,
    "text" => reply,
    "inReplyTo" => m["messageId"]
  )
  puts "🤖 replied to #{m['from']}"

  content_type :json
  Mailkite.reply_ok
end
