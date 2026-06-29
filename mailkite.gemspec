require_relative "lib/mailkite"

Gem::Specification.new do |s|
  s.name = "mailkite"
  s.version = Mailkite::VERSION
  s.summary = "Official MailKite SDK for Ruby"
  s.description = "Send and manage email over your own authenticated domain with MailKite."
  s.authors = ["MailKite"]
  s.homepage = "https://mailkite.dev/docs/libraries"
  s.license = "MIT"
  s.files = ["lib/mailkite.rb"]
  s.require_paths = ["lib"]
  s.required_ruby_version = ">= 2.5"
  s.metadata = { "source_code_uri" => "https://github.com/mailkite/mailkite-ruby" }
end
