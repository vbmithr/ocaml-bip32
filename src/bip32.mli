open Secp256k1

type 'a key
type secret = Secret.t key
type public = Public.t key

val pp_secret : Format.formatter -> secret -> unit
val pp_public : Format.formatter -> public -> unit

val key : 'a key -> 'a
val chaincode : _ key -> Cstruct.t

val of_entropy_exn : Cstruct.t -> secret
val neuterize : secret -> public

val secret_child_of_secret : secret -> Int32.t -> secret
val public_child_of_public : public -> Int32.t -> public
val public_child_of_secret : secret -> Int32.t -> public
val derive_secret : secret -> Int32.t list -> secret
val derive_public : public -> Int32.t list -> public

val base58_of_secret : ?testnet:bool -> secret -> Base58.Bitcoin.t
val base58_of_public : ?testnet:bool -> public -> Base58.Bitcoin.t
val secret_of_base58 : Base58.Bitcoin.t -> secret
val public_of_base58 : Base58.Bitcoin.t -> public
