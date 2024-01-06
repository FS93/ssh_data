module SSHData
  module PublicKey
    class DILITHIUM < Base
      require 'roqs'

      attr_reader :public_key_pointer, :liboqs
      def initialize(algo:, public_key_pointer:)
        unless algo == ALGO_DILITHIUM
          raise DecodeError, "bad algorithm: #{algo.inspect}"
        end

        @algo = algo
        @public_key_pointer = public_key_pointer

        @liboqs = Roqs::SIG.new(algo)

        super(algo: algo)
      end

      # Verify an SSH signature.
      #
      # signed_data - The String message that the signature was calculated over.
      # signature   - The binary String signature with SSH encoding.
      #
      # Returns boolean.
      def verify(signed_data, signature)
        liboqs.verify(signed_data, signature, public_key_pointer)
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
          [:int8_array_pointer, public_key_pointer]
        )
      end

    end
  end
end
