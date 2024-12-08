(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

open Secp256k1
include Bip32_intf

let hardened i = Int32.logand i 0x8000_0000l <> 0l

let pp_print_path ppf i =
  if hardened i
  then Format.fprintf ppf "%ld'" Int32.(logand i 0x7fff_ffffl)
  else Format.fprintf ppf "%ld" i
;;

let zerobuf b =
  for i = 0 to Bigstringaf.length b - 1 do
    Bigstringaf.set b i '\x00'
  done
;;

let create_key ?parent k c path =
  let parent =
    match parent with
    | Some p -> p
    | None ->
      let buf = Bigstringaf.create 20 in
      zerobuf buf;
      buf
  in
  { k; c; path; parent }
;;

module Make (Crypto : CRYPTO) = struct
  let fingerprint ctx k =
    Key.to_bytes ~compress:true ctx k |> Crypto.sha256 |> Crypto.ripemd160
  ;;

  let pp_k ctx ppf k = Hex.pp ppf (Key.to_bytes ctx k |> Hex.of_bigstring)

  let pp : type a. Context.t -> Format.formatter -> a t -> unit =
    fun ctx ppf { k; c; path; parent } ->
    Format.fprintf
      ppf
      "@[<hov 0>key %a@ chaincode %a@ path %a@ parent %a@]"
      (pp_k ctx)
      k
      Hex.pp
      (Hex.of_bigstring c)
      (Format.pp_print_list
         ~pp_sep:(fun ppf () -> Format.pp_print_char ppf '/')
         pp_print_path)
      (List.rev path)
      Hex.pp
      (Hex.of_bigstring parent)
  ;;

  let seed =
    let seed = "Bitcoin seed" in
    Bigstringaf.of_string seed ~off:0 ~len:(String.length seed)
  ;;

  let of_entropy ctx entropy =
    let m = Crypto.hmac_sha512 ~key:seed entropy in
    match Key.read_sk ctx m with
    | Error msg -> Error msg
    | Ok k -> Ok (create_key k (Bigstringaf.sub m ~off:32 ~len:32) [])
  ;;

  let of_entropy_exn ctx entropy =
    match of_entropy ctx entropy with
    | Error msg -> invalid_arg msg
    | Ok sk -> sk
  ;;

  let neuterize : type a. Context.t -> a t -> Key.public t =
    fun ctx k -> { k with k = Key.neuterize_exn ctx k.k }
  ;;

  let derive : type a. Context.t -> a t -> int32 -> a t =
    fun ctx { k; c = key; path; _ } i ->
    match k, hardened i with
    | Key.Pk _, true -> invalid_arg "derive: cannot derive hardened index"
    | Key.Sk _, _ ->
      let buf = Bigstringaf.create 37 in
      let (_ : int) =
        if hardened i
        then (
          Bigstringaf.set buf 0 '\x00';
          Key.write ctx buf ~pos:1 k)
        else (
          let pk = Key.neuterize_exn ctx k in
          Key.write ~compress:true ctx buf pk)
      in
      ();
      Bigstringaf.set_int32_be buf 33 i;
      let derived = Crypto.hmac_sha512 ~key buf in
      let k' = Key.add_tweak ctx k derived in
      let c' = Bigstringaf.sub derived ~off:32 ~len:32 in
      create_key ~parent:(fingerprint ctx (Key.neuterize_exn ctx k)) k' c' (i :: path)
    | Key.Pk _, _ ->
      let buf = Bigstringaf.create 37 in
      zerobuf buf;
      let (_ : int) = Key.write ~compress:true ctx buf k in
      let derived = Crypto.hmac_sha512 ~key buf in
      let k' = Key.add_tweak ctx k derived in
      let c' = Bigstringaf.sub derived ~off:32 ~len:32 in
      create_key ~parent:(fingerprint ctx k) k' c' (i :: path)
  ;;

  let derive_path ctx k path = ListLabels.fold_left path ~init:k ~f:(derive ctx)

  let secret_of_bytes_exn ctx cs =
    let _depth = Bigstringaf.get cs 0 in
    let parent = Bigstringaf.sub cs ~off:1 ~len:4 in
    let child_number = Bigstringaf.get_int32_be cs 5 in
    let chaincode = Bigstringaf.sub cs ~off:9 ~len:32 in
    let secret = Key.read_sk_exn ctx cs ~pos:41 in
    create_key ~parent secret chaincode [ child_number ]
  ;;

  let public_of_bytes_exn ctx cs =
    let _depth = Bigstringaf.get cs 0 in
    let parent = Bigstringaf.sub cs ~off:1 ~len:4 in
    let child_number = Bigstringaf.get_int32_be cs 5 in
    let chaincode = Bigstringaf.sub cs ~off:9 ~len:32 in
    let public = Key.read_pk_exn ctx cs ~pos:40 in
    create_key ~parent public chaincode [ child_number ]
  ;;

  let secret_of_bytes ctx cs =
    try Some (secret_of_bytes_exn ctx cs) with
    | _ -> None
  ;;

  let public_of_bytes ctx cs =
    try Some (public_of_bytes_exn ctx cs) with
    | _ -> None
  ;;

  let secret_of_bytes_exn ctx cs =
    match secret_of_bytes ctx cs with
    | None -> invalid_arg "secret_of_bytes_exn"
    | Some sk -> sk
  ;;

  let public_of_bytes_exn ctx cs =
    match public_of_bytes ctx cs with
    | None -> invalid_arg "public_of_bytes_exn"
    | Some pk -> pk
  ;;

  let to_bigstring : type a. Context.t -> a t -> Bigstringaf.t =
    fun ctx { k; c; path; parent } ->
    let buf = Bigstringaf.create 74 in
    (* not initialized to zero! *)
    Bigstringaf.set buf 0 (List.length path |> Char.chr);
    Bigstringaf.blit parent ~src_off:0 buf ~dst_off:1 ~len:4;
    let path =
      match path with
      | [] -> 0l
      | i :: _ -> i
    in
    Bigstringaf.set_int32_be buf 5 path;
    Bigstringaf.blit c ~src_off:0 buf ~dst_off:9 ~len:32;
    Bigstringaf.set buf 41 '\x00';
    let _nb_written =
      match k with
      | Key.Sk _ -> Key.write ctx buf ~pos:42 k
      | Key.Pk _ -> Key.write ~compress:true ctx buf ~pos:41 k
    in
    buf
  ;;
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
