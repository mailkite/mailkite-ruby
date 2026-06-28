# Server-side login + register.
#
#   A) Your OWN account: call signup (register) or login with email + password, keep the token.
#   B) YOUR USERS' accounts (multi-tenant): the OAuth 2.1 + PKCE flow — send the user to MailKite's
#      hosted page where they LOG IN OR REGISTER, then exchange the returned `code` for a token that
#      *is* that user. Register-or-login is handled on the hosted page; a new user just signs up
#      there and lands back logged in.
#
# Run:  MAILKITE_BASE_URL=https://api.mailkite.dev ruby 05_server_login.rb   # serves on :3000
#       then open http://localhost:3000/login
# Deps: gem install mailkite sinatra

require "json"
require "base64"
require "digest"
require "securerandom"
require "net/http"
require "uri"
require "sinatra"
require "mailkite"

ISSUER = ENV.fetch("MAILKITE_BASE_URL", "https://api.mailkite.dev")
REDIRECT_URI = "http://localhost:3000/callback"

set :port, 3000

def b64url(bytes)
  Base64.urlsafe_encode64(bytes, padding: false)
end

# POST a JSON body; returns [status, parsed_json].
def post_json(url, body)
  uri = URI(url)
  res = Net::HTTP.post(uri, JSON.generate(body), "Content-Type" => "application/json")
  [res.code.to_i, (res.body && !res.body.empty? ? JSON.parse(res.body) : {})]
end

# POST a form-urlencoded body (the OAuth token endpoint); returns parsed_json.
def post_form(url, form)
  res = Net::HTTP.post_form(URI(url), form)
  res.body && !res.body.empty? ? JSON.parse(res.body) : {}
end

# ── A) Server acting as your OWN single account (no redirect) ───────────────────────────────────
def own_account
  status, data = post_json("#{ISSUER}/api/auth/signup",
                           "email" => "you@example.com", "password" => ENV.fetch("MK_PASSWORD"))
  if status == 409  # already registered → log in instead
    _, data = post_json("#{ISSUER}/api/auth/login",
                        "email" => "you@example.com", "password" => ENV.fetch("MK_PASSWORD"))
  end
  mk = Mailkite::Client.new(data["token"])  # the session token works like an API key
  puts "logged in as own account; domains: #{mk.listDomains}"
end

# ── B) OAuth login/register for YOUR USERS ───────────────────────────────────────────────────────
SESSIONS = {}  # demo store: state → { verifier, client_id }. Use a real session store in prod.

get "/login" do
  _, reg = post_json("#{ISSUER}/oauth/register",
                     "client_name" => "My App", "redirect_uris" => [REDIRECT_URI],
                     "grant_types" => ["authorization_code", "refresh_token"], "response_types" => ["code"])
  verifier = b64url(SecureRandom.bytes(32))
  challenge = b64url(Digest::SHA256.digest(verifier))
  state = b64url(SecureRandom.bytes(16))
  SESSIONS[state] = { verifier: verifier, client_id: reg["client_id"] }
  query = URI.encode_www_form(
    "response_type" => "code", "client_id" => reg["client_id"], "redirect_uri" => REDIRECT_URI,
    "scope" => "mcp", "state" => state, "code_challenge" => challenge, "code_challenge_method" => "S256"
  )
  redirect "#{ISSUER}/oauth/authorize?#{query}"
end

get "/callback" do
  sess = SESSIONS.delete(params["state"].to_s)
  halt 400, "unknown state" unless sess
  tok = post_form("#{ISSUER}/oauth/token",
                  "grant_type" => "authorization_code", "code" => params["code"], "redirect_uri" => REDIRECT_URI,
                  "client_id" => sess[:client_id], "code_verifier" => sess[:verifier])
  mk = Mailkite::Client.new(tok["access_token"])  # now act as that user (store refresh_token to renew later)
  content_type :json
  JSON.generate("ok" => true, "message" => "Logged in as the MailKite user.", "domains" => mk.listDomains)
end
