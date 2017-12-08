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

type 'a key = {
  k : 'a ;
  c : Cstruct.t ;
  path : Int32.t list ;
  parent : Cstruct.t ;
}

let pp_secret ppf sk =
  Hex.pp ppf
    (Secret.to_bytes sk |> Cstruct.of_bigarray |> Hex.of_cstruct)

let pp_public ppf pk =
  Hex.pp ppf
    (Public.to_bytes ~compress:true ctx pk |>
     Cstruct.of_bigarray |>
     Hex.of_cstruct)

let pp_key pp ppf { k ; c ; path ; parent } =
  Format.fprintf ppf "@[<hov 0>key %a@ chaincode %a@ path %a@ parent %a@]"
    pp k
    Hex.pp (Hex.of_cstruct c)
    (Format.pp_print_list
       ~pp_sep:(fun ppf () -> Format.pp_print_char ppf '/')
       pp_print_path) (List.rev path)
    Hex.pp (Hex.of_cstruct parent)

type secret = Secret.t key
type public = Public.t key

let pp_secret = pp_key pp_secret
let pp_public = pp_key pp_public

let create ?(parent=Cstruct.create 20) k c path = { k ; c ; path ; parent }
let key { k } = k
let chaincode { c } = c

let of_entropy_exn entropy =
  let key = Cstruct.of_string "Bitcoin seed" in
  let m = hmac ~key entropy in
  match Secret.read ctx m.buffer with
  | None -> invalid_arg "Bip32.of_entropy_exn: invalid seed" ;
  | Some k -> create k (Cstruct.sub m 32 32) []

let secret_child_of_secret { k ; c = key ; path } i =
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
  create ~parent:(fingerprint (Public.of_secret ctx k)) k' c' (i :: path)

let public_child_of_public { k ; c = key ; path } i =
  if hardened i then
    invalid_arg "Bip32.public_child_of_public: cannot derive hardened index" ;
  let cs = Cstruct.create 37 in
  let (_:int) = Public.write ~compress:true ctx cs.buffer k in
  let derived = hmac ~key cs in
  let k' = Public.add_tweak ctx k derived.buffer in
  let c' = Cstruct.sub derived 32 32 in
  create ~parent:(fingerprint k) k' c' (i :: path)

let neuterize sk =
  let pk = Public.of_secret ctx sk.k in
  { sk with k = pk }

let public_child_of_secret sk =
  public_child_of_public (neuterize sk)

let derive_secret sk path =
  ListLabels.fold_left path ~init:sk ~f:secret_child_of_secret

let derive_public pk path =
  ListLabels.fold_left path ~init:pk ~f:public_child_of_public

let to_bytes bytes_of_k { k ; c ; path ; parent } =
  let buf = Buffer.create 74 in
  Buffer.add_char buf (Char.chr (List.length path)) ;
  Buffer.add_string buf Cstruct.(sub parent 0 4 |> to_string) ;
  let cs = Cstruct.create 4 in
  Cstruct.BE.set_uint32 cs 0 (match path with [] -> 0l  | i :: _ -> i) ;
  Buffer.add_string buf (Cstruct.to_string cs) ;
  Buffer.add_string buf (Cstruct.to_string c) ;
  Buffer.add_string buf Cstruct.((bytes_of_k k) |> of_bigarray |> to_string) ;
  Buffer.contents buf

let bytes_of_secret =
  let bytes_of_secret s =
    let cs = Cstruct.create 33 in
    Secret.write cs.buffer ~pos:1 s ;
    cs.buffer in
  to_bytes bytes_of_secret

let bytes_of_public = to_bytes (Public.to_bytes ~compress:true ctx)

let base58_of_secret ?(testnet=false) s =
  let version =
    Base58.Bitcoin.(if testnet then Testnet_BIP32_priv else BIP32_priv) in
  Base58.Bitcoin.create ~version ~payload:(bytes_of_secret s)

let base58_of_public ?(testnet=false) s =
  let version =
    Base58.Bitcoin.(if testnet then Testnet_BIP32_pub else BIP32_pub) in
  Base58.Bitcoin.create ~version ~payload:(bytes_of_public s)

let of_payload_secret cs =
  let _depth = Cstruct.get_uint8 cs 0 in
  let parent = Cstruct.sub cs 1 4 in
  let child_number = Cstruct.BE.get_uint32 cs 5 in
  let chaincode = Cstruct.sub cs 9 32 in
  let secret = Secret.read_exn ctx cs.buffer ~pos:41 in
  create ~parent secret chaincode [child_number]

let of_payload_public cs =
  let _depth = Cstruct.get_uint8 cs 0 in
  let parent = Cstruct.sub cs 1 4 in
  let child_number = Cstruct.BE.get_uint32 cs 5 in
  let chaincode = Cstruct.sub cs 9 32 in
  let public = Public.read_exn ctx cs.buffer ~pos:40 in
  create ~parent public chaincode [child_number]

let secret_of_base58 { Base58.Bitcoin.version ; payload } =
  match version with
  | BIP32_priv | Testnet_BIP32_priv ->
    of_payload_secret (Cstruct.of_string payload)
  | _ -> invalid_arg "Bip32.secret_of_base58: not a BIP32 secret key"

let public_of_base58 { Base58.Bitcoin.version ; payload } =
  match version with
  | BIP32_pub | Testnet_BIP32_pub ->
    of_payload_public (Cstruct.of_string payload)
  | _ -> invalid_arg "Bip32.public_of_base58: not a BIP32 public key"
