require_relative '../spec_helper'

# TODO remove 'focus' tag from test cases

describe SSHData::PublicKey::DILITHIUM do
  let(:liboqs) {Roqs::SIG.new('dilithium5')}
  let(:keypair) {Roqs::SIG.new('dilithium5').genkeypair}
  let(:public_key_pointer) {keypair[0]}
  let(:private_key_pointer) {keypair[1]}

  let(:msg) {"hello, world!"}
  let(:raw_sig) {liboqs.sign(msg, private_key_pointer)}
  let(:sig) {SSHData::Encoding.encode_signature(SSHData::PublicKey::ALGO_DILITHIUM, raw_sig)}

  let(:oqs_openssh_key) {SSHData::PublicKey.parse_openssh(fixture("dilithium5_ca.pub"))}

  subject do
    described_class.new(
      algo: SSHData::PublicKey::ALGO_DILITHIUM,
      public_key_pointer: public_key_pointer
    )
  end

  it "is equal to keys with the same params", focus: true do
    expect(subject).to eq(described_class.new(
      algo: SSHData::PublicKey::ALGO_DILITHIUM,
      public_key_pointer: public_key_pointer
    ))
  end

  it "isn't equal to keys with different params", focus: true do
    expect(subject).not_to eq(described_class.new(
      algo: SSHData::PublicKey::ALGO_DILITHIUM,
      public_key_pointer: Fiddle::Pointer.to_ptr(
        public_key_pointer.to_str[0,public_key_pointer.size-1] +
          # increment last byte by one
          [(public_key_pointer.to_str[-1].unpack("c").first + 1)].pack("c"))
    ))
  end

  it "has an algo", focus: true do
    expect(subject.algo).to eq(SSHData::PublicKey::ALGO_DILITHIUM)
  end

  it "has parameter", focus: true do
    expect(subject.public_key_pointer).to eq(public_key_pointer)
  end

  it "has a liboqs representation", focus: true do
    expect(subject.liboqs).to be_a(Roqs::SIG)
  end

  it "can verify signatures", focus: true do
    expect(subject.verify(msg, sig)).to eq(true)
    expect(subject.verify("wrong", sig)).to be(false)
  end

  it "can parse OQS-openssh-generated keys", focus: true do
    expect { oqs_openssh_key }.not_to raise_error
  end

  it "can be encoded", focus: true do
    expect(oqs_openssh_key.rfc4253).to eq(fixture("dilithium5_ca.pub", binary: true))
  end
  #
  it "can verify certificate signatures", focus: true do
    expect {
      SSHData::Certificate.parse_openssh(fixture("rsa_leaf_for_dilithium5_ca-cert.pub"),
        unsafe_no_verify: false
      )
    }.not_to raise_error
  end
end
