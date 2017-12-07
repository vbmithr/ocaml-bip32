open Secp256k1_internal

type 'a key
type secret = Scalar.t key
type public = Group.t key

val key : 'a key -> 'a
val chaincode : _ key -> Cstruct.t
val of_entropy_exn : Cstruct.t -> secret
val secret_child_of_secret : secret -> Int32.t -> secret
val public_child_of_public : public -> Int32.t -> public
