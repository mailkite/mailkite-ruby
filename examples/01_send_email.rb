# Send an email over a verified domain — the 10-second "it works".
#
# Run:  MAILKITE_API_KEY=mk_live_… ruby 01_send_email.rb
# Deps: gem install mailkite

require "mailkite"

mk = Mailkite::Client.new(ENV["MAILKITE_API_KEY"])

res = mk.send(
  "from" => "hello@yourdomain.com",  # an address on a domain you've verified
  "to" => "ada@example.com",
  "subject" => "Your invoice #1042",
  "html" => "<p>Thanks for your order — receipt attached.</p>"
  # text, cc, bcc, replyTo, attachments, templateId, templateData all supported
)

puts "sent: #{res}"  # → { "id" => "msg_…", "status" => "queued" }
