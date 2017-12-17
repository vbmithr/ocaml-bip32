open Secp256k1

type secret = Secret.t
type public = Public.t

type _ kind =
  | Sk : secret -> secret kind
  | Pk : public -> public kind

type 'a key = private {
  k : 'a kind ;
  c : Cstruct.t ;
  path : Int32.t list ;
  parent : Cstruct.t ;
}

val pp : Format.formatter -> _ key -> unit

val of_entropy_exn : Cstruct.t -> secret key
val neuterize : _ key -> public key

val derive : 'a key -> Int32.t -> 'a key
val derive_path : 'a key -> Int32.t list -> 'a key

val of_base58_sk : Base58.Bitcoin.t -> secret key
val of_base58_pk : Base58.Bitcoin.t -> public key
val to_base58 : ?testnet:bool -> _ key -> Base58.Bitcoin.t
