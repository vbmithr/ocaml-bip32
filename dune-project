(lang dune 3.16)

(name mim)

(generate_opam_files true)

(source
 (github username/reponame))

(authors "Vincent Bernardoff <vb@luminar.eu.org>")

(maintainers "Vincent Bernardoff")

(license LICENSE)

(documentation https://url/to/documentation)

(package
 (name bip32)
 (synopsis "Hierarchical Deterministic Wallets")
 (description "")
 (depends
   ocaml
   dune
   hex
   bigstringaf
   secp256k1
 )
 (tags (crypto bitcoin bip bip32 wallet hdwallet)))

(package
 (name bip32-base58)
 (synopsis "Hierarchical Deterministic Wallets - Base58 addresses")
 (description "")
 (depends
   ocaml
   dune
   base58
   bip32
  (alcotest :with-test)
  (digestif :with-test)
  (hex :with-test)
 )
 (tags (crypto bitcoin bip bip32 wallet hdwallet base58)))

; See the complete stanza docs at https://dune.readthedocs.io/en/stable/reference/dune-project/index.html
