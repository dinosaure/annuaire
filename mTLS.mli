type t

val tls : t -> Tls.Config.server
(** [tls t] returns the actual TLS configuration. *)

val create :
     get:(unit -> Dns_trie.t)
  -> set:(Dns_trie.t -> unit)
  -> CA.cfg
  -> (t * unit Miou.t) option
(** [create ~get ~set cfg] creates a promise which renews TLS certificates from
    a {!type:CA.cfg} configuration and something which is able to give the
    actual TLS certificate to initiate a TLS server. *)
