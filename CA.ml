let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt

let prefix =
  X509.Distinguished_name.
    [ Relative_distinguished_name.singleton (CN "Annuaire") ]

let cacert_dn =
  let open X509.Distinguished_name in
  prefix @ [ Relative_distinguished_name.singleton (CN "Annuaire") ]

let _365d = Ptime.Span.v (365, 0L)
let _30d = Ptime.Span.v (30, 0L)
let _10s = Ptime.Span.of_int_s 10
let ( let* ) = Result.bind

let make domain_name ~seed ?(lifetime = _365d) () =
  let* domain_name = Domain_name.of_string domain_name in
  let* domain_name = Domain_name.host domain_name in
  let pk =
    let g = Mirage_crypto_rng.(create ~seed (module Fortuna)) in
    let priv, _ = Mirage_crypto_ec.P256.Dsa.generate ~g () in
    `P256 priv
  in
  let now = Mirage_ptime.now () in
  let valid_from = Option.get Ptime.(sub_span now _10s) in
  let* valid_until =
    Ptime.add_span valid_from lifetime
    |> Option.to_result ~none:(msgf "End time out of range")
  in
  let* ca_csr = X509.Signing_request.create cacert_dn pk in
  let extensions =
    let open X509 in
    let open X509.Extension in
    let key_id = Public_key.id Signing_request.((info ca_csr).public_key) in
    let domain_name = Domain_name.to_string domain_name in
    empty
    |> add Subject_alt_name (true, General_name.(singleton DNS [ domain_name ]))
    |> add Basic_constraints (true, (false, None))
    |> add Key_usage (true, [ `Digital_signature ])
    |> add Ext_key_usage (true, [ `Server_auth ])
    |> add Subject_key_id (false, key_id)
  in
  let* cert =
    X509.Signing_request.sign ~valid_from ~valid_until ~extensions ca_csr pk
      cacert_dn
    |> Result.map_error (msgf "%a" X509.Validation.pp_signature_error)
  in
  Ok (cert, pk, valid_until)

let tlsa_of_cert cert =
  let pk = X509.Certificate.public_key cert in
  let data = X509.Public_key.fingerprint ~hash:`SHA256 pk in
  {
    Dns.Tlsa.cert_usage= Dns.Tlsa.Domain_issued_certificate
  ; selector= Dns.Tlsa.Subject_public_key_info
  ; matching_type= Dns.Tlsa.SHA256
  ; data
  }

type cfg = {
    domain: [ `host ] Domain_name.t
  ; ipaddr: Ipaddr.V4.t
  ; lifetime: Ptime.Span.t
  ; ttl: int32
  ; seed: string
  ; mutable count: int
}

let domain { domain; _ } = domain
let ttl { ttl; _ } = ttl
let lifetime { lifetime; _ } = lifetime
let count { count; _ } = count

let cfg ?(lifetime = _365d) ?ttl ?(count = 0) ~seed ipaddr domain =
  (* Here, we "cap" our [ttl] to 3600 seconds (one hour) but if the user ask to
     have a lifetime smaller than 1h, we "cap" the ttl to this lifetime. *)
  let ttl =
    let ttl = Option.map Int32.to_int ttl in
    let ttl = Option.map Ptime.Span.of_int_s ttl in
    let ttl = Option.value ~default:(Ptime.Span.of_int_s 3600) ttl in
    if Ptime.Span.compare lifetime ttl < 0 then
      Option.get (Ptime.Span.to_int_s lifetime) |> Int32.of_int
    else 3600l
  in
  { domain; ipaddr; lifetime; ttl; count; seed }

let generate cfg =
  let ( let* ) = Result.bind in
  let lifetime = cfg.lifetime in
  let domain = Domain_name.to_string cfg.domain in
  cfg.count <- cfg.count + 1;
  let seed =
    let prf = `SHA256
    and password = cfg.seed
    and salt = "annuaire"
    and count = cfg.count
    and dk_len = 32l in
    Pbkdf.pbkdf2 ~prf ~password ~salt ~count ~dk_len
  in
  let* cert, pk, valid_until = make domain ~seed ~lifetime () in
  let tlsa = tlsa_of_cert cert in
  let chain = ([ cert ], pk) in
  let* cfg = Tls.Config.server ~certificates:(`Single chain) () in
  Ok (cfg, tlsa, valid_until)

let regenerate ~count ~seed:password =
  let seed =
    let prf = `SHA256 and salt = "annuaire" and dk_len = 32l in
    Pbkdf.pbkdf2 ~prf ~password ~salt ~count ~dk_len
  in
  let pk =
    let g = Mirage_crypto_rng.(create ~seed (module Fortuna)) in
    let priv, _ = Mirage_crypto_ec.P256.Dsa.generate ~g () in
    X509.Private_key.public (`P256 priv)
  in
  let data = X509.Public_key.fingerprint ~hash:`SHA256 pk in
  {
    Dns.Tlsa.cert_usage= Dns.Tlsa.Domain_issued_certificate
  ; selector= Dns.Tlsa.Subject_public_key_info
  ; matching_type= Dns.Tlsa.SHA256
  ; data
  }

let zone cfg =
  let domain = Domain_name.raw cfg.domain in
  let soa = Dns.Soa.create domain in
  let ns = Domain_name.Host_set.singleton cfg.domain in
  let a = Ipaddr.V4.Set.singleton cfg.ipaddr in
  let map =
    Dns.Rr_map.empty
    |> Dns.Rr_map.add Dns.Rr_map.Soa soa
    |> Dns.Rr_map.add Dns.Rr_map.Ns (cfg.ttl, ns)
    |> Dns.Rr_map.add Dns.Rr_map.A (cfg.ttl, a)
  in
  Domain_name.Map.singleton domain map

let tlsa_name ?(port = 853) cfg =
  let raw = Domain_name.raw cfg.domain in
  let n = Domain_name.prepend_label_exn raw "_tcp" in
  Domain_name.prepend_label_exn n (Fmt.str "_%d" port)

let gen_name cfg =
  let raw = Domain_name.raw cfg.domain in
  Domain_name.prepend_label_exn raw "_gen"

let with_tlsa_entries ?(port = 853) cfg entries trie =
  let set =
    List.fold_left
      (Fun.flip Dns.Rr_map.Tlsa_set.add)
      Dns.Rr_map.Tlsa_set.empty entries
  in
  let name = tlsa_name ~port cfg in
  Dns_trie.replace name Dns.Rr_map.Tlsa (cfg.ttl, set) trie

let with_gen ?counts cfg trie =
  let name = gen_name cfg in
  let counts = Option.value ~default:[ cfg.count ] counts in
  let set =
    List.fold_left
      (fun acc count -> Dns.Rr_map.Txt_set.add (Fmt.str "%d" count) acc)
      Dns.Rr_map.Txt_set.empty counts
  in
  Dns_trie.replace name Dns.Rr_map.Txt (cfg.ttl, set) trie

let zone ?(port = 853) cfg ~tlsa trie =
  Dns_trie.insert_map (zone cfg) trie
  |> with_tlsa_entries ~port cfg [ tlsa ]
  |> with_gen cfg
