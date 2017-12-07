open Secp256k1

type 'a key
type secret = Secret.t key
type public = Public.t key

val key : 'a key -> 'a
val chaincode : _ key -> Cstruct.t
val of_entropy_exn : Cstruct.t -> secret
val neuterize : secret -> public
val derive_secret : secret -> Int32.t list -> secret
val derive_public : public -> Int32.t list -> public
