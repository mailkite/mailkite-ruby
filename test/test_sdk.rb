# Unit tests for the MailKite Ruby SDK. Covers every public function:
#   - request (auth, content-type, JSON body, errors, base-url trim, empty body)
#   - one thin method per endpoint (correct verb + path + body)
#   - verify_webhook / verifyWebhook (valid / tampered / wrong-secret /
#     malformed / replay window)
#
# Run with:  ruby test/test_sdk.rb
require "minitest/autorun"
require "webrick"
require "openssl"
require "json"
require_relative "../lib/mailkite"

# ---- in-process mock server -------------------------------------------------
STATE = { status: 200, body: { "ok" => true }, last: nil }

def reply(status, body)
  STATE[:status] = status
  STATE[:body] = body
end

SECRET = "whsec_mailkite_test"
PAYLOAD = '{"type":"email.received","id":"evt_123","message":"It works."}'
V1 = "3d790f831e170ddba4d001f27532bf2c1fc68ebed52eef72fe453dfa1196b03c"
HEADER = "t=1750000000000,v1=#{V1}"

def fresh_header(secret, body)
  t = (Time.now.to_f * 1000).to_i
  sig = OpenSSL::HMAC.hexdigest("SHA256", secret, "#{t}.#{body}")
  "t=#{t},v1=#{sig}"
end

# Servlet that overrides `service`, so it records and replies for every HTTP
# verb (mount_proc only handles GET/POST).
class MockServlet < WEBrick::HTTPServlet::AbstractServlet
  def service(req, res)
    STATE[:last] = {
      method: req.request_method,
      path: req.path,
      headers: req.header.transform_values { |v| v.is_a?(Array) ? v.first : v },
      raw: req.body.to_s,
    }
    res.status = STATE[:status]
    res["content-type"] = "application/json"
    res.body = STATE[:body].nil? ? "" : JSON.generate(STATE[:body])
  end
end

class SDKTest < Minitest::Test
  @@server = nil
  @@thread = nil

  def self.start_server
    @@server = WEBrick::HTTPServer.new(
      BindAddress: "127.0.0.1", Port: 0,
      Logger: WEBrick::Log.new(File::NULL), AccessLog: [],
    )
    @@server.mount("/", MockServlet)
    @@thread = Thread.new { @@server.start }
    @@server.config[:Port]
  end

  PORT = start_server
  BASE = "http://127.0.0.1:#{PORT}"
  KEY = "mk_live_test"

  Minitest.after_run { @@server&.shutdown }

  def mk
    @mk ||= Mailkite::Client.new(KEY, BASE)
  end

  # ---- constructor ----------------------------------------------------------
  def test_base_url_trim
    assert_equal "https://api.x.dev", Mailkite::Client.new("k", "https://api.x.dev///").instance_variable_get(:@base_url)
  end

  # ---- request --------------------------------------------------------------
  def test_request_auth_and_json
    reply(200, { "id" => "x", "status" => "queued" })
    out = mk.request("POST", "/v1/send", { "a" => 1 })
    last = STATE[:last]
    assert_equal "Bearer #{KEY}", last[:headers]["authorization"]
    assert_includes last[:headers]["content-type"], "application/json"
    assert_equal({ "a" => 1 }, JSON.parse(last[:raw]))
    assert_equal({ "id" => "x", "status" => "queued" }, out)
  end

  def test_request_no_body
    reply(200, [])
    mk.request("GET", "/api/domains")
    assert_equal "", STATE[:last][:raw]
  end

  def test_request_empty_body_returns_nil
    reply(204, nil)
    assert_nil mk.request("DELETE", "/api/x")
  end

  def test_request_error_maps_to_exception
    reply(404, { "error" => "not found" })
    err = assert_raises(Mailkite::Error) { mk.request("GET", "/api/messages/nope") }
    assert_equal 404, err.status
    assert_equal "not found", err.message
    assert_equal({ "error" => "not found" }, err.body)
  end

  def test_request_error_without_error_field
    reply(500, { "nope" => true })
    err = assert_raises(Mailkite::Error) { mk.request("GET", "/x") }
    assert_equal 500, err.status
  end

  # ---- endpoint methods -----------------------------------------------------
  def test_endpoint_methods
    cases = [
      [-> { mk.send({ "from" => "a", "to" => "b", "subject" => "s", "text" => "t" }) }, "POST", "/v1/send", { "from" => "a", "to" => "b", "subject" => "s", "text" => "t" }],
      [-> { mk.listDomains }, "GET", "/api/domains", nil],
      [-> { mk.createDomain({ "domain" => "x.dev" }) }, "POST", "/api/domains", { "domain" => "x.dev" }],
      [-> { mk.getDomain("dom_1") }, "GET", "/api/domains/dom_1", nil],
      [-> { mk.deleteDomain("dom_1") }, "DELETE", "/api/domains/dom_1", nil],
      [-> { mk.verifyDomain("dom_1") }, "POST", "/api/domains/dom_1/verify", nil],
      [-> { mk.setWebhook("dom_1", { "url" => "https://h.dev" }) }, "PUT", "/api/domains/dom_1/webhook", { "url" => "https://h.dev" }],
      [-> { mk.deleteWebhook("dom_1") }, "DELETE", "/api/domains/dom_1/webhook", nil],
      [-> { mk.testWebhook("dom_1") }, "POST", "/api/domains/dom_1/webhook/test", nil],
      [-> { mk.listRoutes }, "GET", "/api/routes", nil],
      [-> { mk.createRoute({ "match" => "*@x", "action" => "webhook", "destination" => "u" }) }, "POST", "/api/routes", { "match" => "*@x", "action" => "webhook", "destination" => "u" }],
      [-> { mk.listMessages }, "GET", "/api/messages", nil],
      [-> { mk.getMessage("msg_1") }, "GET", "/api/messages/msg_1", nil],
      [-> { mk.retryDelivery("dlv_1") }, "POST", "/api/deliveries/dlv_1/retry", nil],
    ]
    cases.each do |call, method, path, body|
      reply(200, { "ok" => true })
      call.call
      last = STATE[:last]
      assert_equal method, last[:method], path
      assert_equal path, last[:path]
      if body.nil?
        assert_equal "", last[:raw]
      else
        assert_equal body, JSON.parse(last[:raw])
      end
    end
  end

  # ---- verify_webhook -------------------------------------------------------
  def test_verify_valid
    assert_equal true, Mailkite.verify_webhook(HEADER, PAYLOAD, SECRET, 0)
    assert_equal true, mk.verifyWebhook(HEADER, PAYLOAD, SECRET, 0)
  end

  def test_verify_tampered_body
    assert_equal false, Mailkite.verify_webhook(HEADER, "#{PAYLOAD} ", SECRET, 0)
  end

  def test_verify_wrong_secret
    assert_equal false, Mailkite.verify_webhook(HEADER, PAYLOAD, "whsec_wrong", 0)
  end

  def test_verify_malformed
    ["", "garbage", "t=1750000000000", "v1=#{V1}", "t=nan,v1=#{V1}", nil].each do |h|
      assert_equal false, Mailkite.verify_webhook(h, PAYLOAD, SECRET, 0), "header: #{h.inspect}"
    end
  end

  def test_verify_replay_window
    # Fixed vector is far in the past → default 5-min window rejects it.
    assert_equal false, Mailkite.verify_webhook(HEADER, PAYLOAD, SECRET)
    # Freshly signed event → passes the default window.
    assert_equal true, Mailkite.verify_webhook(fresh_header(SECRET, PAYLOAD), PAYLOAD, SECRET)
  end
end
