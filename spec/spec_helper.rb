require "ssh_data"
require "ed25519"

# roqs logs debug messages to STDOUT - temporarily redirect STDOUT to /dev/null
original_stdout = $stdout.dup
$stdout.reopen('/dev/null', 'w')
$stdout.sync = true
require 'roqs'
$stdout.reopen(original_stdout)

require "rspec-parameterized"

RSpec.configure do |config|
  config.color_mode = :off
end

REPO_PATH    = File.expand_path(File.join(__FILE__, "..", ".."))
FIXTURE_PATH = File.expand_path(File.join(REPO_PATH, "spec", "fixtures"))
OQS_OPENSSH_SSHKEYGEN_PATH = ""

def fixture(name, binary: false, pem: false)
  data = File.read(File.join(FIXTURE_PATH, name))
  return data unless binary

  if pem
    SSHData::Encoding.decode_pem(data, "OPENSSH PRIVATE KEY")
  else
    SSHData.key_parts(data)[1]
  end
end

def ssh_keygen_fingerprint(name, algo, priv: false, oqs: false)
  if oqs
    ssh_keygen_path = OQS_OPENSSH_SSHKEYGEN_PATH
  else
    ssh_keygen_path = "ssh-keygen"
  end
  out = `#{ssh_keygen_path} #{"-e" if priv} -E #{algo} -l -f #{File.join(FIXTURE_PATH, name)}`
  out.split(":", 2).last.split(" ").first
end

def ec_private_to_public(private_key)
  algorithm_identifier = OpenSSL::ASN1::Sequence.new([
    OpenSSL::ASN1::ObjectId.new("id-ecPublicKey"),
    OpenSSL::ASN1::ObjectId.new(private_key.group.curve_name)
  ])

  subject_public_key = OpenSSL::ASN1::BitString.new(private_key.public_key.to_bn.to_s(2))
  spki = OpenSSL::ASN1::Sequence.new([algorithm_identifier, subject_public_key])
  OpenSSL::PKey::EC.new(spki.to_der)
end
