open Bip32

module type S = sig
  val of_base58_sk : Base58.Bitcoin.t -> secret key
  val of_base58_pk : Base58.Bitcoin.t -> public key
  val to_base58 : ?testnet:bool -> _ key -> Base58.Bitcoin.t
end

module Make (Crypto : CRYPTO) : S
