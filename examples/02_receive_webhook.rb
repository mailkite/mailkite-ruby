# Receive inbound email as a webhook — and VERIFY the HMAC signature before trusting it.
#
# MailKite POSTs a signed `email.received` event to your URL. Always verify the
# `x-mailkite-signature` header against your webhook secret so inbound mail can't be forged.
#
# Run:  MAILKITE_WEBHOOK_SECRET=whsec_… ruby 02_receive_webhook.rb   # serves on :3000
# Deps: gem install mailkite sinatra

require "json"
require "sinatra"
require "mailkite"

mk = Mailkite::Client.new(ENV.fetch("MAILKITE_API_KEY", "unused-for-verify"))
SECRET = ENV.fetch("MAILKITE_WEBHOOK_SECRET")

set :port, 3000

post "/hooks/mailkite" do
  raw = request.body.read  # the RAW body — re-serialized JSON breaks the HMAC
  signature = request.env["HTTP_X_MAILKITE_SIGNATURE"]
  halt 401, "bad signature" unless mk.verifyWebhook(signature, raw, SECRET)

  event = JSON.parse(raw)
  if event["type"] == "email.received"
    m = event["message"] || event
    puts "📬 #{m['from']} → #{m['to']}: #{m['subject']}"
    # …store it, notify a channel, kick off a workflow…
  end

  content_type :json
  Mailkite.reply_ok  # 200 acknowledges; return a control body to mark spam / drop / block
end
