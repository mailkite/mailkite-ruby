# MailKite SDK for Ruby.
#
# Shape shared by every MailKite SDK: one low-level `request` plus one thin
# method per API endpoint. Zero dependencies — uses the standard library.
#
#   require "mailkite"
#   mk = Mailkite::Client.new(ENV["MAILKITE_API_KEY"])
#   res = mk.send({ "from" => ..., "to" => ..., "subject" => ..., "text" => ... })

require "net/http"
require "uri"
require "json"
require "openssl"
require "base64"
require "cgi"

module Mailkite
  VERSION = "0.9.0"
  DEFAULT_BASE_URL = "https://api.mailkite.dev"
  # Reject webhook events older than this (ms) to block replays. Pass 0 to disable.
  DEFAULT_TOLERANCE_MS = 5 * 60 * 1000

  # Verify an `x-mailkite-signature` header on an inbound webhook delivery.
  # Local HMAC-SHA256 check — no network call. Pass the raw, unparsed body.
  def self.verify_webhook(signature, payload, secret, tolerance_ms = DEFAULT_TOLERANCE_MS)
    return false unless signature.is_a?(String) && !signature.empty?

    parts = {}
    signature.split(",").each do |seg|
      i = seg.index("=")
      next unless i
      parts[seg[0...i].strip] = seg[(i + 1)..].strip
    end
    t = parts["t"]
    v1 = parts["v1"]
    return false if t.nil? || v1.nil? || t.empty? || v1.empty? || !t.match?(/\A-?\d+\z/)

    # The t in the header is milliseconds since the epoch.
    if tolerance_ms && tolerance_ms > 0
      return false if ((Time.now.to_f * 1000) - t.to_i).abs > tolerance_ms
    end

    expected = OpenSSL::HMAC.hexdigest("SHA256", secret, "#{t}.#{payload}")
    secure_compare(expected, v1)
  rescue StandardError
    false
  end

  # Length-independent constant-time string compare (no openssl >= 2.2 needed).
  def self.secure_compare(a, b)
    return false unless a.bytesize == b.bytesize

    diff = 0
    a.bytes.each_with_index { |byte, i| diff |= byte ^ b.getbyte(i) }
    diff.zero?
  end

  # The canonical body to return from a webhook handler so MailKite marks the
  # delivery acknowledged. Returns the exact string `{"status":"ok"}`.
  def self.reply_ok
    '{"status":"ok"}'
  end

  # Control-mode reply telling MailKite to mark the message as spam.
  # Returns the exact string `{"status":"spam"}`.
  def self.reply_spam
    '{"status":"spam"}'
  end

  # Control-mode reply telling MailKite to drop (discard) the message.
  # Returns the exact string `{"status":"drop"}`.
  def self.reply_drop
    '{"status":"drop"}'
  end

  # Control-mode reply telling MailKite to block the sender.
  # Returns the exact string `{"status":"ok","actions":[{"type":"block-sender"}]}`.
  def self.reply_block_sender
    '{"status":"ok","actions":[{"type":"block-sender"}]}'
  end

  # Encrypt a UTF-8 string to a customer RSA public key (SPKI/PEM), producing the
  # MailKite at-rest envelope as a compact JSON string. Hybrid scheme: a fresh
  # AES-256-GCM content key encrypts the data, then the raw key is wrapped with
  # RSA-OAEP (SHA-256). Local only — no network.
  def self.encrypt(plaintext, public_key)
    pub = OpenSSL::PKey.read(public_key)
    fp = OpenSSL::Digest::SHA256.hexdigest(pub.to_der)

    raw_key = OpenSSL::Random.random_bytes(32)
    iv = OpenSSL::Random.random_bytes(12)

    cipher = OpenSSL::Cipher.new("aes-256-gcm")
    cipher.encrypt
    cipher.key = raw_key
    cipher.iv = iv
    body = cipher.update(plaintext.to_s.dup.force_encoding("UTF-8")) + cipher.final
    ciphertext = body + cipher.auth_tag # GCM ct with 16-byte tag appended

    wrapped = pub.encrypt(raw_key, rsa_padding_mode: "oaep", rsa_oaep_md: "sha256", rsa_mgf1_md: "sha256")

    JSON.generate({
      "v" => 1,
      "keyAlg" => "RSA-OAEP-256",
      "fp" => fp,
      "enc" => "A256GCM",
      "iv" => Base64.strict_encode64(iv),
      "wrappedKey" => Base64.strict_encode64(wrapped),
      "ciphertext" => Base64.strict_encode64(ciphertext),
    })
  end

  # Decrypt a MailKite at-rest envelope (JSON string) with the matching RSA
  # private key (PEM), returning the original UTF-8 plaintext. Local only.
  def self.decrypt(envelope, private_key)
    env = envelope.is_a?(String) ? JSON.parse(envelope) : envelope
    priv = OpenSSL::PKey.read(private_key)

    iv = Base64.strict_decode64(env["iv"])
    wrapped = Base64.strict_decode64(env["wrappedKey"])
    ct = Base64.strict_decode64(env["ciphertext"])
    body = ct[0...-16]
    tag = ct[-16..]

    raw_key = priv.decrypt(wrapped, rsa_padding_mode: "oaep", rsa_oaep_md: "sha256", rsa_mgf1_md: "sha256")

    cipher = OpenSSL::Cipher.new("aes-256-gcm")
    cipher.decrypt
    cipher.key = raw_key
    cipher.iv = iv
    cipher.auth_tag = tag
    (cipher.update(body) + cipher.final).force_encoding("UTF-8")
  end

  class Error < StandardError
    attr_reader :status, :body

    def initialize(status, message, body = nil)
      super(message)
      @status = status
      @body = body
    end
  end

  class Client
    VERBS = {
      "GET" => Net::HTTP::Get,
      "POST" => Net::HTTP::Post,
      "PUT" => Net::HTTP::Put,
      "PATCH" => Net::HTTP::Patch,
      "DELETE" => Net::HTTP::Delete,
    }.freeze

    def initialize(api_key, base_url = DEFAULT_BASE_URL)
      @api_key = api_key
      @base_url = base_url.sub(%r{/+\z}, "")
    end

    # Low-level request. Every method below is a one-liner on top of this.
    def request(method, path, body = nil)
      uri = URI(@base_url + path)
      req = VERBS.fetch(method).new(uri)
      req["Authorization"] = "Bearer #{@api_key}"
      unless body.nil?
        req["Content-Type"] = "application/json"
        req.body = JSON.generate(body)
      end

      perform(req, uri)
    end

    # Raw-binary request used by uploadAttachment for `bytes`/`path` uploads:
    # the body is the file bytes themselves (not JSON, not multipart) and the
    # Content-Type names the file's media type. Same auth + response parsing.
    def request_binary(bytes, filename:, content_type:, retention_days: nil)
      query = { "filename" => filename }
      query["retentionDays"] = retention_days unless retention_days.nil?
      qs = query.map { |k, v| "#{CGI.escape(k)}=#{CGI.escape(v.to_s)}" }.join("&")
      uri = URI("#{@base_url}/v1/attachments?#{qs}")
      req = Net::HTTP::Post.new(uri)
      req["Authorization"] = "Bearer #{@api_key}"
      req["Content-Type"] = content_type
      req.body = bytes
      perform(req, uri)
    end

    # Send a prepared Net::HTTP request and parse the JSON response (shared by
    # `request` and `request_binary`).
    def perform(req, uri)
      res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https") { |http| http.request(req) }
      text = res.body
      data = text && !text.empty? ? JSON.parse(text) : nil
      code = res.code.to_i
      unless code >= 200 && code < 300
        message = data.is_a?(Hash) ? data["error"] : nil
        raise Error.new(code, message || res.message || "HTTP #{code}", data)
      end
      data
    end

    # --- Sending --------------------------------------------------------
    # message keys: from, to, text/html, etc. `subject` is optional when a
    # template supplies it. Pass `templateId` to render a stored template and
    # `templateData` (a hash) to fill its variables.
    def send(message)
      request("POST", "/v1/send", message)
    end

    # Extension → MIME map for raw-binary attachment uploads (default
    # application/octet-stream when an extension is unknown).
    ATTACHMENT_MIME = {
      "pdf" => "application/pdf",
      "png" => "image/png",
      "jpg" => "image/jpeg",
      "jpeg" => "image/jpeg",
      "gif" => "image/gif",
      "webp" => "image/webp",
      "svg" => "image/svg+xml",
      "csv" => "text/csv",
      "txt" => "text/plain",
      "html" => "text/html",
      "json" => "application/json",
      "zip" => "application/zip",
      "doc" => "application/msword",
      "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "xls" => "application/vnd.ms-excel",
      "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "ics" => "text/calendar",
      "ical" => "text/calendar",
    }.freeze

    # Upload a file and get back a secure, time-limited URL to reference as a
    # send() attachment ({ filename, url }) or link inline — instead of
    # base64-inlining large files on every send. Provide the file ONE of four
    # ways via the `file` hash (priority order):
    #   1. url            — MailKite fetches & re-hosts the remote file
    #   2. bytes          — raw binary string, uploaded directly
    #   3. path           — local file read off disk, then uploaded as bytes
    #   4. content        — base64 string (the original behavior)
    # Plus optional filename, contentType, and retentionDays.
    def uploadAttachment(file)
      url = file["url"] || file[:url]
      bytes = file["bytes"] || file[:bytes]
      path = file["path"] || file[:path]
      content = file["content"] || file[:content]
      filename = file["filename"] || file[:filename]
      content_type = file["contentType"] || file[:contentType]
      retention_days = file["retentionDays"] || file[:retentionDays]

      if url
        body = { "url" => url }
        body["filename"] = filename unless filename.nil?
        body["contentType"] = content_type unless content_type.nil?
        body["retentionDays"] = retention_days unless retention_days.nil?
        return request("POST", "/v1/attachments", body)
      end

      if bytes || path
        if path
          bytes = File.binread(path)
          filename ||= File.basename(path)
          content_type ||= ATTACHMENT_MIME[File.extname(path).downcase.delete_prefix(".")]
        end
        content_type ||= "application/octet-stream"
        return request_binary(bytes, filename: filename, content_type: content_type, retention_days: retention_days)
      end

      if content
        body = { "content" => content, "filename" => filename }
        body["contentType"] = content_type unless content_type.nil?
        body["retentionDays"] = retention_days unless retention_days.nil?
        return request("POST", "/v1/attachments", body)
      end

      raise ArgumentError, "uploadAttachment requires one of: path, bytes, url, or content"
    end

    # Run an inbound message through an AI agent. message keys: text (required),
    # plus optional subject/from/html/routeId/address/model.
    def agent(message)
      request("POST", "/v1/agent", message)
    end

    # Route an inbound message to its configured destination. message keys: from
    # (required), plus optional routeId/address/subject/text/html.
    def route(message)
      request("POST", "/v1/route", message)
    end

    # --- Domains --------------------------------------------------------
    def listDomains
      request("GET", "/api/domains")
    end

    def createDomain(body)
      request("POST", "/api/domains", body)
    end

    def getDomain(id)
      request("GET", "/api/domains/#{id}")
    end

    def deleteDomain(id)
      request("DELETE", "/api/domains/#{id}")
    end

    def verifyDomain(id)
      request("POST", "/api/domains/#{id}/verify")
    end

    def setWebhook(id, body)
      request("PUT", "/api/domains/#{id}/webhook", body)
    end

    def deleteWebhook(id)
      request("DELETE", "/api/domains/#{id}/webhook")
    end

    def testWebhook(id)
      request("POST", "/api/domains/#{id}/webhook/test")
    end

    def checkDomainAvailability(domain)
      request("GET", "/api/domains/register/check?domain=#{CGI.escape(domain)}")
    end

    def registerDomain(body)
      request("POST", "/api/domains/register", body)
    end

    # --- Routes ---------------------------------------------------------
    def listRoutes
      request("GET", "/api/routes")
    end

    def createRoute(body)
      request("POST", "/api/routes", body)
    end

    # --- Templates ------------------------------------------------------
    def listTemplates
      request("GET", "/api/templates")
    end

    def listBaseTemplates
      request("GET", "/api/templates/base")
    end

    def getTemplate(id)
      request("GET", "/api/templates/#{id}")
    end

    def createTemplate(body)
      request("POST", "/api/templates", body)
    end

    # --- Messages & deliveries -----------------------------------------
    def listMessages
      request("GET", "/api/messages")
    end

    def getMessage(id)
      request("GET", "/api/messages/#{id}")
    end

    def retryDelivery(id)
      request("POST", "/api/deliveries/#{id}/retry")
    end

    # --- Lists ----------------------------------------------------------
    def listLists
      request("GET", "/api/lists")
    end

    def createList(body)
      request("POST", "/api/lists", body)
    end

    def getList(id)
      request("GET", "/api/lists/#{id}")
    end

    def updateList(id, body)
      request("PATCH", "/api/lists/#{id}", body)
    end

    def deleteList(id)
      request("DELETE", "/api/lists/#{id}")
    end

    def listListContacts(id)
      request("GET", "/api/lists/#{id}/contacts")
    end

    def addListContacts(id, body)
      request("POST", "/api/lists/#{id}/contacts", body)
    end

    def removeListContact(id, contactId)
      request("DELETE", "/api/lists/#{id}/contacts/#{contactId}")
    end

    # --- Broadcasts -----------------------------------------------------
    def listBroadcasts
      request("GET", "/api/broadcasts")
    end

    def createBroadcast(body)
      request("POST", "/api/broadcasts", body)
    end

    def getBroadcast(id)
      request("GET", "/api/broadcasts/#{id}")
    end

    def updateBroadcast(id, body)
      request("PATCH", "/api/broadcasts/#{id}", body)
    end

    def deleteBroadcast(id)
      request("DELETE", "/api/broadcasts/#{id}")
    end

    def sendBroadcast(id, body)
      request("POST", "/api/broadcasts/#{id}/send", body)
    end

    # --- Docs -----------------------------------------------------------
    # Semantic search over the MailKite docs. PUBLIC — no auth required.
    # Returns { "query" => ..., "matches" => [...] }.
    def semanticSearch(query)
      request("GET", "/v1/docs/search?query=#{CGI.escape(query)}")
    end

    # --- Webhooks -------------------------------------------------------
    # Instance wrapper around Mailkite.verify_webhook, so you can verify on an
    # existing client. No network call; no API key required.
    def verifyWebhook(signature, payload, secret, tolerance_ms = DEFAULT_TOLERANCE_MS)
      Mailkite.verify_webhook(signature, payload, secret, tolerance_ms)
    end

    # Instance wrappers around the module-level crypto helpers. No network call.
    def reply_ok
      Mailkite.reply_ok
    end

    def reply_spam
      Mailkite.reply_spam
    end

    def reply_drop
      Mailkite.reply_drop
    end

    def reply_block_sender
      Mailkite.reply_block_sender
    end

    def encrypt(plaintext, public_key)
      Mailkite.encrypt(plaintext, public_key)
    end

    def decrypt(envelope, private_key)
      Mailkite.decrypt(envelope, private_key)
    end
  end
end
