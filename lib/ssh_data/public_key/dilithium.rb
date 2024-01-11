module SSHData
  module PublicKey
    class DILITHIUM < Base
      # roqs logs debug messages to STDOUT - temporarily redirect STDOUT to /dev/null
      original_stdout = $stdout.dup
      $stdout.reopen('/dev/null', 'w')
      $stdout.sync = true
      require 'roqs'
      $stdout.reopen(original_stdout)

      attr_reader :public_key_pointer, :liboqs
      def initialize(algo:, public_key_pointer:)
        unless algo == ALGO_DILITHIUM
          raise DecodeError, "bad algorithm: #{algo.inspect}"
        end

        @algo = algo
        @public_key_pointer = public_key_pointer

        @liboqs = Roqs::SIG.new(PublicKey::LIBOQS_ALGO_NAMES[algo])

        super(algo: algo)
      end

      # Verify an SSH signature.
      #
      # signed_data - The String message that the signature was calculated over.
      # signature   - The binary String signature with SSH encoding.
      #
      # Returns boolean.
      def verify(signed_data, signature)
        sig_algo, raw_sig, _ = Encoding.decode_signature(signature)

        if sig_algo != ALGO_DILITHIUM
          raise DecodeError, "bas signature algorithm: #{sig_algo.inspect}"
        end

        liboqs.verify(signed_data, raw_sig, public_key_pointer)
      end

      # Is this public key equal to another public key?
      #
      # other - Another SSHData::PublicKey::Base instance to compare with.
      #
      # Returns boolean.
      def ==(other)
        super && other.public_key_pointer.to_str == public_key_pointer.to_str
      end

      # RFC4253 binary encoding of the public key.
      #
      # Returns a binary String.
      def rfc4253
        Encoding.encode_fields(
          [:string, algo],
          [:int8_array_pointer, public_key_pointer]
        )
      end

    end
  end
end
