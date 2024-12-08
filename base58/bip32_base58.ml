(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

open Secp256k1
open Bip32

include Bip32_base58_intf

module Make (Crypto : CRYPTO) (B58 : Base58.S with type version := Base58.bitcoin_version) = struct
  open Make(Crypto)

  let to_base58 (type a) ?(testnet=false) ctx (s : a t) =
    let open Base58 in
    let version =
      match s.k with
      | Key.Sk _ -> (if testnet then Testnet_BIP32_priv else BIP32_priv)
      | Key.Pk _ -> (if testnet then Testnet_BIP32_pub else BIP32_pub)
    in
    let payload = to_bigstring ctx s |> Bigstringaf.to_string in
    B58.create ~version ~payload

  let of_base58_sk ctx { B58.version ; payload } =
    match version with
    | BIP32_priv | Testnet_BIP32_priv ->
      secret_of_bytes ctx (Bigstringaf.of_string payload ~off:0 ~len:(String.length payload))
    | _ -> None

  let of_base58_pk ctx { B58.version ; payload } =
    match version with
    | BIP32_pub | Testnet_BIP32_pub ->
      public_of_bytes ctx (Bigstringaf.of_string payload ~off:0 ~len:(String.length payload))
    | _ -> None

  let of_base58_sk_exn ctx b58 =
    match of_base58_sk ctx b58 with
    | Some sk -> sk
    | None -> invalid_arg "of_base58_sk_exn"

  let of_base58_pk_exn ctx b58 =
    match of_base58_pk ctx b58 with
    | Some pk -> pk
    | None -> invalid_arg "of_base58_pk_exn"
end

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
