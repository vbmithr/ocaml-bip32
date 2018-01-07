open Secp256k1

module type CRYPTO = sig
  val sha256 : Cstruct.t -> Cstruct.t
  val ripemd160 : Cstruct.t -> Cstruct.t
  val hmac_sha512 : key:Cstruct.t -> Cstruct.t -> Cstruct.t

  val ctx : Context.t
end

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

val create_key :
  ?parent:Cstruct.t -> 'a kind -> Cstruct.t -> Int32.t list -> 'a key

module type S = sig
  val pp : Format.formatter -> _ key -> unit
  val of_entropy : Cstruct.t -> secret key option
  val neuterize : _ key -> public key
  val derive : 'a key -> Int32.t -> 'a key
  val derive_path : 'a key -> Int32.t list -> 'a key
  val to_bytes : 'a key -> string
end

module Make (Crypto : CRYPTO) : S
