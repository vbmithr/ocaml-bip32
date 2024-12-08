open Secp256k1
open Bip32

module type S = sig
  type b58

  val of_base58_sk : Context.t -> b58 -> Key.secret t option
  val of_base58_pk : Context.t -> b58 -> Key.public t option
  val of_base58_sk_exn : Context.t -> b58 -> Key.secret t
  val of_base58_pk_exn : Context.t -> b58 -> Key.public t
  val to_base58 : ?testnet:bool -> Context.t -> _ t -> b58
end
