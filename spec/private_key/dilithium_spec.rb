# frozen_string_literal: true
require_relative '../spec_helper'

describe SSHData::PrivateKey::DILITHIUM do
  let(:liboqs)              { Roqs::SIG.new('dilithium5')}
  let(:keypair)             { liboqs.genkeypair }
  let(:public_key_pointer)  { keypair[0] }
  let(:private_key_pointer) { keypair[1] }
  let(:message)             { "hello, world!" }
  let(:cert_key)            { SSHData::PrivateKey::DSA.generate.public_key }

  let(:oqs_openssh_key) { SSHData::PrivateKey.parse(fixture("dilithium5_leaf_for_rsa_ca")) }

  subject { described_class.from_liboqs(keypair) }

  it "can be generated" do
    expect {
      described_class.generate
    }.not_to raise_error
  end

  it "can sign messages" do
    expect(subject.public_key.verify(message, subject.sign(message))).to eq(true)
  end

  it "can sign message with ALGO_DILITHIUM" do
    sig = subject.sign(message, algo: SSHData::PublicKey::ALGO_DILITHIUM)
    expect(subject.public_key.verify(message, sig)).to eq(true)
  end

  it "raises when trying to sign with bad algo" do
    expect {
      subject.sign(message, algo: SSHData::PublicKey::ALGO_RSA)
    }.to raise_error(SSHData::AlgorithmError)
  end

  it "can issue a certificate" do
    cert = subject.issue_certificate(
      public_key: cert_key,
      key_id: "some ident"
    )

    algo, _ = SSHData::Encoding.decode_signature(cert.signature)

    expect(algo).to eq(SSHData::PublicKey::ALGO_DILITHIUM)
    expect(cert.verify).to be(true)
  end

  it "can issue a certificate with ALGO_DILITHIUM signature algo" do
    cert = subject.issue_certificate(
      public_key: cert_key,
      key_id: "some ident",
      signature_algo: "ssh-dilithium5"
    )

    algo, _ = SSHData::Encoding.decode_signature(cert.signature)

    expect(algo).to eq(SSHData::PublicKey::ALGO_DILITHIUM)
    expect(cert.verify).to be(true)
  end

  it "raises when trying to sign a certificate with bad signature algo" do
    expect {
      subject.issue_certificate(
        public_key: cert_key,
        key_id: "some ident",
        signature_algo: SSHData::PublicKey::ALGO_RSA
      )
    }.to raise_error(SSHData::AlgorithmError)
  end

  it "has an algo" do
    expect(subject.algo).to eq(SSHData::PublicKey::ALGO_DILITHIUM)
  end

  it "has params" do
    expect(subject.private_key_pointer.to_str).to eq(private_key_pointer.to_str)
    expect(subject.public_key_pointer.to_str).to eq(public_key_pointer.to_str)
  end

  it "has a comment" do
    expect(subject.comment).to eq("")
  end

  it "has a liboqs representation" do
    expect(subject.liboqs).to be_a(Roqs::SIG)
  end

  it "has a public key" do
    expect(subject.public_key).to be_a(SSHData::PublicKey::DILITHIUM)
    expect(subject.public_key.public_key_pointer.to_str).to eq(public_key_pointer.to_str)
  end

  it "can parse OQS-OpenSSH generated keys" do
    expect(oqs_openssh_key).to be_an(Array)
    expect(oqs_openssh_key.size).to eq(1)
    expect(oqs_openssh_key.first).to be_an(SSHData::PrivateKey::DILITHIUM)
  end

  it "can be cleaned up" do
    # TODO right test for SSHData::PrivateKey::DILITHIUM.cleanup
    expect(subject.public_key_pointer.freed?).to be(false)
    expect(subject.private_key_pointer.freed?).to be(false)
    public_key_before_free = subject.public_key_pointer.to_str
    private_key_before_free = subject.private_key_pointer.to_str

    subject.cleanup

    expect(subject.public_key_pointer.freed?).to be(true)
    expect(subject.private_key_pointer.freed?).to be(true)
    expect(subject.public_key_pointer.to_str).not_to eq(public_key_before_free)
    expect(subject.private_key_pointer.to_str).not_to eq(private_key_before_free)
  end
end
