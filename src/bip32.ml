open Secp256k1_internal

let hmac ~key data =
  let key = Cstruct.to_bigarray key in
  let data = Cstruct.to_bigarray data in
  Digestif.SHA512.Bigstring.hmac ~key data |>
  Cstruct.of_bigarray

let point ge sk =
  let gej = Group.Jacobian.of_fields () in
  Group.Jacobian.mul gej Group.g sk ;
  Group.Jacobian.get_ge ge gej

let order =
  let res = Num.zero () in
  Scalar.order_get_num res ;
  res

type 'a key = {
  k : 'a ;
  c : Cstruct.t ;
}

type secret = Scalar.t key
type public = Group.t key

let create k c = { k ; c }
let key { k } = k
let chaincode { c } = c

let of_entropy_exn entropy =
  let key = Cstruct.of_string "Bitcoin seed" in
  let m = hmac ~key entropy in
  let k = Scalar.zero () in
  if not (Scalar.set_b32 k (Cstruct.sub m 0 32)) then
    invalid_arg "Bip32.of_entropy_exn: invalid seed" ;
  create k (Cstruct.sub m 32 32)

let hardened i = i < 0x7fff_ffffl

let secret_child_key cs sk =
  let kn = Num.zero () in
  let res = Num.zero () in
  Num.set_bin res (Cstruct.sub cs 0 32) ;
  Scalar.get_num kn sk ;
  Num.modulo kn order ;
  Num.add res res kn ;
  if Num.is_zero res then
    invalid_arg "Bip32.secret_child_key: derived key is zero" ;
  let cs = Cstruct.create 32 in
  Num.get_bin cs res ;
  let res = Scalar.const () in
  if not (Scalar.set_b32 res cs) then
    invalid_arg "Bip32.secret_child_key: derived key is invalid" ;
  res

let secret_child_of_secret { k ; c = key } i =
  let derived =
    let buf = Cstruct.create 37 in
    if hardened i then begin
      Scalar.get_b32 (Cstruct.sub buf 1 32) k ;
      Cstruct.BE.set_uint32 buf 33 i ;
      hmac ~key buf
    end
    else begin
      let ge = Group.of_fields () in
      point ge k ;
      let (_:Cstruct.t) = Group.to_pubkey ~compress:true buf ge in
      Cstruct.BE.set_uint32 buf 33 i ;
      hmac ~key buf
    end in
  let k' = secret_child_key derived k in
  let c' = Cstruct.sub derived 32 32 in
  create k' c'

let public_child_key cs pk =
  let scalar = Scalar.zero () in
  if not (Scalar.set_b32 scalar (Cstruct.sub cs 0 32)) then
    invalid_arg "Bip32.public_child_key: derived key is invalid" ;
  let ge = Group.of_fields () in
  point ge scalar ;
  let res = Group.Jacobian.of_fields () in
  Group.Jacobian.add_ge res res ge ;
  Group.Jacobian.add_ge res res pk ;
  if Group.Jacobian.is_infinity res then
    invalid_arg "Bip32.public_child_key: derived key is invalid" ;
  Group.Jacobian.get_ge ge res ;
  ge

let public_child_of_public { k ; c = key } i =
  if hardened i then
    invalid_arg "Bip32.public_child_of_public: hardened child undefined" ;
  let cs = Cstruct.create 33 in
  let (_:Cstruct.t) = Group.to_pubkey ~compress:true cs k in
  let derived = hmac ~key cs in
  let k' = public_child_key derived k in
  let c' = Cstruct.sub derived 32 32 in
  create k' c'
