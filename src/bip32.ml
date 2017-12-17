open Secp256k1

let ctx = Context.create [Sign]

let hmac ~key data =
  let key = Cstruct.to_bigarray key in
  let data = Cstruct.to_bigarray data in
  Digestif.SHA512.Bigstring.hmac ~key data |>
  Cstruct.of_bigarray

let fingerprint k =
  let module R = Digestif.RMD160.Bigstring in
  let module S = Digestif.SHA256.Bigstring in
  let d = R.digest (S.digest (Public.to_bytes ~compress:true ctx k)) in
  Cstruct.of_bigarray d

let hardened i =
  Int32.logand i 0x8000_0000l <> 0l

let pp_print_path ppf i =
  if hardened i then
    Format.fprintf ppf "%ld'" Int32.(logand i 0x7fff_ffffl)
  else
    Format.fprintf ppf "%ld" i

type secret = Secret.t
type public = Public.t

type _ kind =
  | Sk : secret -> secret kind
  | Pk : public -> public kind

let pp_kind :
  type a. Format.formatter -> a kind -> unit = fun ppf -> function
  | Sk sk ->
    Hex.pp ppf
      (Secret.to_bytes sk |> Cstruct.of_bigarray |> Hex.of_cstruct)
  | Pk pk ->
    Hex.pp ppf
      (Public.to_bytes ~compress:true ctx pk |>
       Cstruct.of_bigarray |>
       Hex.of_cstruct)

type 'a key = {
  k : 'a kind ;
  c : Cstruct.t ;
  path : Int32.t list ;
  parent : Cstruct.t ;
}

let pp :
  type a. Format.formatter -> a key -> unit = fun ppf { k ; c ; path ; parent } ->
  Format.fprintf ppf "@[<hov 0>key %a@ chaincode %a@ path %a@ parent %a@]"
    pp_kind k
    Hex.pp (Hex.of_cstruct c)
    (Format.pp_print_list
       ~pp_sep:(fun ppf () -> Format.pp_print_char ppf '/')
       pp_print_path) (List.rev path)
    Hex.pp (Hex.of_cstruct parent)

let create_sk ?(parent=Cstruct.create 20) k c path = { k = Sk k ; c ; path ; parent }
let create_pk ?(parent=Cstruct.create 20) k c path = { k = Pk k ; c ; path ; parent }

let of_entropy_exn entropy =
  let key = Cstruct.of_string "Bitcoin seed" in
  let m = hmac ~key entropy in
  match Secret.read ctx m.buffer with
  | None -> invalid_arg "Bip32.of_entropy_exn: invalid seed" ;
  | Some k -> create_sk k (Cstruct.sub m 32 32) []

let neuterize : type a. a key -> public key = fun k ->
  match k.k with
  | Sk sk ->
    let pk = Public.of_secret ctx sk in
    { k with k = Pk pk }
  | Pk _ -> k

let derive : type a. a key -> Int32.t -> a key = fun { k ; c = key ; path } i ->
  match k, hardened i with
  | Pk _, true ->
    invalid_arg "derive: cannot derive hardened index" ;
  | Sk k, _ ->
    let buf = Cstruct.create 37 in
    if hardened i then
      Secret.write buf.buffer ~pos:1 k
    else begin
      let pk = Public.of_secret ctx k in
      let (_:int) = Public.write ~compress:true ctx buf.buffer pk in
      ()
    end ;
    Cstruct.BE.set_uint32 buf 33 i ;
    let derived = hmac ~key buf in
    let k' = Secret.add_tweak ctx k derived.buffer in
    let c' = Cstruct.sub derived 32 32 in
    create_sk ~parent:(fingerprint (Public.of_secret ctx k)) k' c' (i :: path)
  | Pk k, _ ->
    let cs = Cstruct.create 37 in
    let (_:int) = Public.write ~compress:true ctx cs.buffer k in
    let derived = hmac ~key cs in
    let k' = Public.add_tweak ctx k derived.buffer in
    let c' = Cstruct.sub derived 32 32 in
    create_pk ~parent:(fingerprint k) k' c' (i :: path)

let derive_path : type a. a key -> Int32.t list -> a key = fun k path ->
  ListLabels.fold_left path ~init:k ~f:derive

let to_bytes : type a. a key -> string = fun { k ; c ; path ; parent } ->
  let buf = Buffer.create 74 in
  Buffer.add_char buf (Char.chr (List.length path)) ;
  Buffer.add_string buf Cstruct.(sub parent 0 4 |> to_string) ;
  let cs = Cstruct.create 4 in
  Cstruct.BE.set_uint32 cs 0 (match path with [] -> 0l  | i :: _ -> i) ;
  Buffer.add_string buf (Cstruct.to_string cs) ;
  Buffer.add_string buf (Cstruct.to_string c) ;
  begin match k with
    | Sk sk ->
      let cs = Cstruct.create 33 in
      Secret.write cs.buffer ~pos:1 sk ;
      Buffer.add_string buf (Cstruct.to_string cs)
    | Pk pk ->
      let pk = Public.to_bytes ~compress:true ctx pk in
      Buffer.add_string buf Cstruct.(of_bigarray pk |> to_string)
  end ;
  Buffer.contents buf

let to_base58 :
  type a. ?testnet:bool -> a key -> Base58.Bitcoin.t = fun ?(testnet=false) s ->
  let version =
    match s.k with
    | Sk _ -> Base58.Bitcoin.(if testnet then Testnet_BIP32_priv else BIP32_priv)
    | Pk _ -> Base58.Bitcoin.(if testnet then Testnet_BIP32_pub else BIP32_pub)
  in
  Base58.Bitcoin.create ~version ~payload:(to_bytes s)

let of_payload_secret cs =
  let _depth = Cstruct.get_uint8 cs 0 in
  let parent = Cstruct.sub cs 1 4 in
  let child_number = Cstruct.BE.get_uint32 cs 5 in
  let chaincode = Cstruct.sub cs 9 32 in
  let secret = Secret.read_exn ctx cs.buffer ~pos:41 in
  create_sk ~parent secret chaincode [child_number]

let of_payload_public cs =
  let _depth = Cstruct.get_uint8 cs 0 in
  let parent = Cstruct.sub cs 1 4 in
  let child_number = Cstruct.BE.get_uint32 cs 5 in
  let chaincode = Cstruct.sub cs 9 32 in
  let public = Public.read_exn ctx cs.buffer ~pos:40 in
  create_pk ~parent public chaincode [child_number]

let of_base58_sk { Base58.Bitcoin.version ; payload } =
  match version with
  | BIP32_priv | Testnet_BIP32_priv ->
    of_payload_secret (Cstruct.of_string payload)
  | _ -> invalid_arg "Bip32.secret_of_base58: not a BIP32 secret key"

let of_base58_pk { Base58.Bitcoin.version ; payload } =
  match version with
  | BIP32_pub | Testnet_BIP32_pub ->
    of_payload_public (Cstruct.of_string payload)
  | _ -> invalid_arg "Bip32.public_of_base58: not a BIP32 public key"
