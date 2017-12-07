open Secp256k1

let ctx = Context.create []

let hmac ~key data =
  let key = Cstruct.to_bigarray key in
  let data = Cstruct.to_bigarray data in
  Digestif.SHA512.Bigstring.hmac ~key data |>
  Cstruct.of_bigarray

type 'a key = {
  k : 'a ;
  c : Cstruct.t ;
}

type secret = Secret.t key
type public = Public.t key

let create k c = { k ; c }
let key { k } = k
let chaincode { c } = c

let of_entropy_exn entropy =
  let key = Cstruct.of_string "Bitcoin seed" in
  let m = hmac ~key entropy in
  match Secret.read ctx m.buffer with
  | None -> invalid_arg "Bip32.of_entropy_exn: invalid seed" ;
  | Some k -> create k (Cstruct.sub m 32 32)

let hardened i = i < 0x7fff_ffffl

let secret_child_of_secret { k ; c = key } i =
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
  create k' c'

let public_child_of_public { k ; c = key } i =
  if hardened i then
    invalid_arg "Bip32.public_child_of_public: cannot derive hardened index" ;
  let cs = Cstruct.create 37 in
  let (_:int) = Public.write ~compress:true ctx cs.buffer k in
  let derived = hmac ~key cs in
  let k' = Public.add_tweak ctx k derived.buffer in
  let c' = Cstruct.sub derived 32 32 in
  create k' c'

let neuterize { k ; c } =
  let k = Public.of_secret ctx k in
  create k c

let public_child_of_secret sk =
  public_child_of_public (neuterize sk)

let derive_secret sk path =
  ListLabels.fold_left path ~init:sk ~f:secret_child_of_secret

let derive_public pk path =
  ListLabels.fold_left path ~init:pk ~f:public_child_of_public
