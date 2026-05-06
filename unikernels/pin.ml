let src = Logs.Src.create "pageblanche.pin"
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let ( let* ) = Result.bind

module Log = (val Logs.src_log src : Logs.LOG)

type t = Dns.Rr_map.Tlsa_set.t Atomic.t

type error =
  [ `Msg of string
  | `No_data of [ `raw ] Domain_name.t * Dns.Soa.t
  | `No_domain of [ `raw ] Domain_name.t * Dns.Soa.t ]

let v initial = Atomic.make initial
let get t = Atomic.get t
let set t v = Atomic.set t v

let leaf_spki_matches pins leaf =
  let pk = X509.Certificate.public_key leaf in
  let fg = X509.Public_key.fingerprint ~hash:`SHA256 pk in
  Dns.Rr_map.Tlsa_set.exists
    (fun tlsa ->
      tlsa.Dns.Tlsa.cert_usage = Dns.Tlsa.Domain_issued_certificate
      && tlsa.Dns.Tlsa.selector = Dns.Tlsa.Subject_public_key_info
      && tlsa.Dns.Tlsa.matching_type = Dns.Tlsa.SHA256
      && String.equal tlsa.Dns.Tlsa.data fg)
    pins

let authenticator t : X509.Authenticator.t =
 fun ?ip:_ ~host:_ certs ->
  match certs with
  | [] -> error_msgf "Certificate not found"
  | leaf :: _ ->
      let pins = Atomic.get t in
      if leaf_spki_matches pins leaf then Ok None
      else begin
        let pk = X509.Certificate.public_key leaf in
        let fg = X509.Public_key.fingerprint ~hash:`SHA256 pk in
        Log.warn (fun m ->
            m "Upstream cert SPKI %s does not match any of %d pinned TLSA(s)"
              (Ohex.encode fg)
              (Dns.Rr_map.Tlsa_set.cardinal pins));
        error_msgf "Invalid chain"
      end

let counts_of_txts set =
  let fn str acc =
    match int_of_string_opt (String.trim str) with
    | Some n when n > 0 -> n :: acc
    | _ -> acc
  in
  Dns.Rr_map.Txt_set.fold fn set []

let ask_counts udp he ipaddr domain =
  let nameservers = (`Tcp, [ `Plaintext (ipaddr, 53) ]) in
  let dns = Mnet_dns.create ~nameservers (udp, he) in
  let raw = Domain_name.raw domain in
  let gen = Domain_name.prepend_label_exn raw "_gen" in
  Logs.debug (fun m -> m "Asking %a" Domain_name.pp gen);
  let* _ttl, txts = Mnet_dns.get_resource_record dns Dns.Rr_map.Txt gen in
  Logs.debug (fun m -> m "Got a TXT response from %a" Domain_name.pp gen);
  match counts_of_txts txts with
  | [] -> error_msgf "No valid counter at %a" Domain_name.pp gen
  | counts -> Ok (gen, counts)

let tlsas_of_counts ~seed counts =
  let fn acc count = Dns.Rr_map.Tlsa_set.add (CA.regenerate ~count ~seed) acc in
  List.fold_left fn Dns.Rr_map.Tlsa_set.empty counts

let _60s = 60l
let _1d = 86_400l
let _1s = 1l

let renew t dns _gen seed =
  let rec go () =
    let pins_before = get t in
    Logs.info (fun m -> m "Asking for %a" Domain_name.pp _gen);
    match Mnet_dns.get_resource_record dns Dns.Rr_map.Txt _gen with
    | Error err ->
        let pp_err ppf = function
          | `Msg msg -> Fmt.string ppf msg
          | `No_data _ -> Fmt.string ppf "no TXT record"
          | `No_domain _ -> Fmt.string ppf "domain does not exist"
        in
        Logs.warn (fun m ->
            m "upstream counter refresh failed (%a); retrying in 1mn" pp_err err);
        Mkernel.sleep (60 * 1_000_000_000);
        go ()
    | Ok (ttl, txts) ->
        begin match counts_of_txts txts with
        | [] ->
            Logs.warn (fun m ->
                m "No valid counter at %a; retrying in 1mn" Domain_name.pp _gen);
            Mkernel.sleep (60 * 1_000_000_000);
            go ()
        | counts ->
            Logs.info (fun m ->
                m "Server's counter(s): %a" Fmt.(Dump.list int) counts);
            let new_pins = tlsas_of_counts ~seed counts in
            if not (Dns.Rr_map.Tlsa_set.equal new_pins pins_before) then
              set t new_pins;
            let next_secs =
              let half = Int32.div ttl 2l in
              if half = 0l then _1s
              else if Int32.compare half _1d > 0 then _1d
              else half
            in
            Mkernel.sleep (Int32.to_int next_secs * 1_000_000_000);
            go ()
        end
  in
  go ()

let launch udp he ipaddr domain seed =
  let* _gen, counts = ask_counts udp he ipaddr domain in
  let pin = v (tlsas_of_counts ~seed counts) in
  let nameservers, tls =
    let authenticator = authenticator pin in
    let cfg = Tls.Config.client ~authenticator ~peer_name:domain () in
    let cfg = Result.get_ok cfg in
    let tls = (`Tcp, `Tls (cfg, ipaddr, 853)) in
    let nameservers =
      (`Tcp, [ `Tls (cfg, ipaddr, 853); `Plaintext (ipaddr, 53) ])
    in
    (nameservers, tls)
  in
  let dns = Mnet_dns.create ~nameservers (udp, he) in
  let prm = Miou.async @@ fun () -> renew pin dns _gen seed in
  Ok (tls, prm)
