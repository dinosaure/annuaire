type cfg

val cfg :
     ?lifetime:Ptime.span
  -> ?ttl:int32
  -> ?count:int
  -> seed:string
  -> Ipaddr.V4.t
  -> [ `host ] Domain_name.t
  -> cfg

val domain : cfg -> [ `host ] Domain_name.t
val ttl : cfg -> int32
val lifetime : cfg -> Ptime.span
val count : cfg -> int

val generate :
  cfg -> (Tls.Config.server * Dns.Tlsa.t * Ptime.t, [> `Msg of string ]) result
(** [generate cfg] generates new TLS certificate with a TLSA value and when the
    certificate expires. Each call to [generate] increments an internal counter
    so that the private key is never the same. This counter is available via the
    {!val:count} function and is published under the domain
    [_gen.<domain>.local] (as a TXT field). *)

val regenerate : count:int -> seed:string -> Dns.Tlsa.t
(** [regenerate ~counter ~seed] generates the TLSA value from [counter] and
    [seed]. It permits to regenerate the fingerprint of the public key (and
    verify a TLS communication) without asking the TLSA through an insecure
    communication if we know [counter] (which can be retrieved via
    [_gen.<domain>.local]) and the [seed]. *)

val with_tlsa_entries :
  ?port:int -> cfg -> Dns.Tlsa.t list -> Dns_trie.t -> Dns_trie.t
(** [with_tlsa_entries] fills the given [trie] with given TLSA entries. *)

val with_gen : ?counts:int list -> cfg -> Dns_trie.t -> Dns_trie.t
(** [with_gen ?counts cfg trie] publishes one TXT entry per [count] under
    [_gen.<domain>.local]. Defaults to [[CA.count cfg]] when [counts] is
    omitted. During a rotation overlap, both the previous and the next counts
    should be published so a client can regenerate either fingerprint. *)

val gen_name : cfg -> [ `raw ] Domain_name.t
(** [gen_name cfg] returns the [_gen.<domain>] name where the counter is
    published. *)

val zone : ?port:int -> cfg -> tlsa:Dns.Tlsa.t -> Dns_trie.t -> Dns_trie.t
(** [zone cfg ~tlsa trie] fills the given [trie] with a local zone (SOA, A and
    TLSA). *)
