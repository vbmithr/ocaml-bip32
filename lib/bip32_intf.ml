open Secp256k1

module type CRYPTO = sig
  val sha256 : Bigstringaf.t -> Bigstringaf.t
  val ripemd160 : Bigstringaf.t -> Bigstringaf.t
  val hmac_sha512 : key:Bigstringaf.t -> Bigstringaf.t -> Bigstringaf.t
end

type 'a t = {
  k : 'a Key.t ;
  c : Bigstringaf.t ;
  path : Int32.t list ;
  parent : Bigstringaf.t ;
}

module type S = sig
  val pp : Context.t -> Format.formatter -> _ t -> unit
  val of_entropy : Context.t -> Bigstringaf.t -> (Key.secret t, string) result
  val of_entropy_exn : Context.t -> Bigstringaf.t -> Key.secret t
  val neuterize : Context.t -> _ t -> Key.public t
  val derive : Context.t -> 'a t -> Int32.t -> 'a t
  val derive_path : Context.t -> 'a t -> Int32.t list -> 'a t

  val secret_of_bytes : Context.t -> Bigstringaf.t -> Key.secret t option
  val secret_of_bytes_exn : Context.t -> Bigstringaf.t -> Key.secret t
  val public_of_bytes : Context.t -> Bigstringaf.t -> Key.public t option
  val public_of_bytes_exn : Context.t -> Bigstringaf.t -> Key.public t

  val to_bigstring: Context.t -> _ t -> Bigstringaf.t
end
