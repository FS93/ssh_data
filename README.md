# ssh_data [<kbd>docs</kbd>](https://rubydoc.info/github/github/ssh_data/master)

This is a Ruby library for processing SSH keys and certificates.

The scope of this project is limited to processing and directly using keys and certificates. It can be used to generate SSH private keys, verify signatures using public keys, sign data using private keys, issue certificates using private keys, and parse certificates and public and private keys. This library supports RSA, DSA, ECDSA, ED25519<sup>[*](#ed25519-support)</sup> and DILITHIUM-5<sup>[**](#dilithium-support) keys. This library does not offer or intend to offer functionality for SSH connectivity, processing of SSH wire protocol data, or processing of other key formats or types.

**Project Status:** Used by @github in production

## Installation

```
gem install ssh_data
```

## Usage

```ruby
require "ssh_data"

key_data = File.read("~/.ssh/id_rsa.pub")
key = SSHData::PublicKey.parse_openssh(key_data)
#=> <SSHData::PublicKey::RSA>

cert_data = = File.read("~/.ssh/id_rsa-cert.pub")
cert = SSHData::Certificate.parse_openssh(cert_data)
#=> <SSHData::PublicKey::Certificate>

cert.key_id
#=> "mastahyeti"

cert.public_key
#=> <SSHData::PublicKey::RSA>
```

## ED25519 support

Ruby's standard library does not include support for ED25519, though the algorithm is implemented by the [`ed25519` Gem](https://rubygems.org/gems/ed25519). This library can parse ED25519 public and private keys itself, but in order to generate keys or sign or verify messages, the calling application must load the `ed25519` Gem itself. This avoids the necessity of installing or loading this third party dependency when the calling application is only interested in parsing keys.

```ruby
require "ssh_data"

key_data = File.read("~/.ssh/id_ed25519")
key = SSHData::PrivateKey.parse_openssh(key_data).first
#=> <SSHData::PrivateKey::ED25519>

SSHData::PrivateKey::ED25519.generate
#=> raises SSHData::AlgorithmError

require "ed25519"

SSHData::PrivateKey::ED25519.generate
#=> <SSHData::PrivateKey::ED25519>
```

## Dilithium support

Support for the quantum secure digital signature [Dilithium](https://pq-crystals.org/dilithium/index.shtml), a finalist 
in the [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography), is 
provided using the [`roqs` Gem](https://rubygems.org/gems/roqs) that itself wraps the [`liboqs` C library](https://openquantumsafe.org/liboqs/). 

As binary formats for public / private keys and signatures have not yet been standardized, consistency with
the [OQS-OpenSSH](https://openquantumsafe.org/applications/ssh.html#oqs-openssh) fork has been seeked:
public keys (typically `id_dilithium5.pub`) and private keys (typically `id_dilithium5`) generated with 

```bash
ssh-keygen -t ssh-dilithium5 -f ~/.ssh/id_dilithium5
``` 
(see [here](https://github.com/open-quantum-safe/openssh#generating-quantum-safe-authentication-keys))
can be parsed.


```ruby
require "ssh_data"

key_data = File.read("~/.ssh/id_dilithium5")
private_key = SSHData::PrivateKey.parse_openssh(key_data).first
#=> <SSHData::PrivateKey::Dilithium>
public_key = private_key.public_key

m = "message"

# Signing
 
sig = private_key.sign(m)
#=> Signature binary string

# Verifying

public_key.verify(m, sig)
#=> true
public_key.verify("some other string", sig)
#=> false

# Cleanup
# -> roqs generates private and public key as Fiddle::Pointer, which have to be
#    freed manually after usage
 
private_key.cleanup

```

## Contributions

This project is not currently seeking contributions for new features or functionality, though bug fixes are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for more information.

## License

This project is published under the MIT license. See [LICENSE.md](LICENSE.md) for mor information.
