module SSHData
  module PrivateKey
    class DILITHIUM < Base
      require 'roqs'

      attr_reader :public_key_pointer, :private_key_pointer, :liboqs

      # Generate a new keypair
      #
      # Returns a PublicKey::Base subclass instance.
      def self.generate
        from_liboqs(Roqs::SIG.new('dilithium5').genkeypair)
      end

      # Import a liboqs Dilithium keypair
      #
      # keypair - An Array containing public_key_pointer and private_key_pointer, both instances of Fiddle::Pointer
      #
      # Returns a DILITHIUM instance.
      def from_liboqs(keypair)
        new(
          algo: PublicKey::ALGO_DILITHIUM,
          public_key_pointer: keypair[0],
          private_key_pointer: keypair[1],
          comment: ""
        )
      end

      def initialize(algo:, public_key_pointer:, private_key_pointer:, comment:)
        unless algo == PublicKey::ALGO_DILITHIUM
          raise DecodeError, "bad algorithm: #{algo.inspect}"
        end

        super(algo: algo, comment: comment)

        @liboqs = Roqs::SIG.new(algo)

        @public_key_pointer = public_key_pointer
        @private_key_pointer = private_key_pointer

        @public_key = PublicKey::DILITHIUM.new(algo: algo, public_key_pointer: public_key_pointer)
      end

      # Make an Dilithium signature.
      #
      # signed_data - The String message over which to calculate the signature.
      #
      # Returns a binary String signature.
      def sign(signed_data, algo: nil)
        algo ||= self.algo
        raise AlgorithmError unless algo == self.algo
        raw_sig = liboqs.sign(signed_data, private_key_pointer)
        Encoding.encode_signature(algo, raw_sig)
      end

      # Frees the public_key_pointer and private_key_pointer.
      # Should be executed as soon as the keypair is not needed anymore.
      def cleanup
        liboqs.free(public_key_pointer)
        liboqs.free(private_key_pointer)
        liboqs.cleanup
      end

    end
  end
end

