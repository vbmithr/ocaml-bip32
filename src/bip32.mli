(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

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

(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff

   Permission to use, copy, modify, and/or distribute this software for any
   purpose with or without fee is hereby granted, provided that the above
   copyright notice and this permission notice appear in all copies.

   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
  ---------------------------------------------------------------------------*)
