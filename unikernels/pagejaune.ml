module RNG = Mirage_crypto_rng.Fortuna

let _2s = 2_000_000_000
let ( let@ ) finally fn = Fun.protect ~finally fn
let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
let rng = Mkernel.map rng Mkernel.[]
let ( let* ) = Result.bind
let guard ~err fn = if fn () then Ok () else Error err
let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

let compact () =
  let rec go ~minor ~hwm =
    Mkernel.sleep _2s;
    let stat = Gc.quick_stat () in
    let busy = stat.Gc.minor_collections - minor > 2 in
    (* NOTE(dinosaure): here, we call [Gc.compact] when:
       - our unikernel is not too much busy with minor collections ([<= 2])
         since our last iteration
       - we have more [heap_words] than expected (more than 1,5 times from our 
         last iterations)

       We monitor these values every 2 seconds. *)
    if (not busy) && stat.Gc.heap_words > hwm then begin
      Gc.compact ();
      let stat = Gc.quick_stat () in
      go ~minor:stat.Gc.minor_collections ~hwm:(stat.Gc.heap_words * 3 / 2)
    end
    else go ~minor:stat.Gc.minor_collections ~hwm
  in
  let stat = Gc.quick_stat () in
  go ~minor:stat.Gc.minor_collections ~hwm:(stat.Gc.heap_words * 3 / 2)

let first_cidrv4 lst =
  let fn = function Ipaddr.V4 _ -> true | _ -> false in
  List.find fn lst |> function Ipaddr.V4 cidrv4 -> cidrv4 | _ -> assert false

let run _ stack cache_size features authenticator domain lifetime seed =
  Mkernel.(run [ rng; stack ]) @@ fun rng (daemon, tcp, udp) () ->
  let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
  let@ () = fun () -> Mnet.kill daemon in
  let rng = Mirage_crypto_rng.generate in
  let root = Dns_resolver_shared.Root.reserved in
  let primary = Dns_server.Primary.create ~rng root in
  let tls =
    let addresses = Mnet.addresses daemon in
    let ipaddr = Ipaddr.V4.Prefix.address (first_cidrv4 addresses) in
    let lifetime = Ptime.Span.of_int_s (Duration.to_sec lifetime) in
    CA.cfg ~lifetime ~seed ipaddr domain
  in
  let cfg = Tls.Config.client ~authenticator () in
  let cfg = Result.get_ok cfg in
  let _resolver, daemon =
    Resolver.create ~features ~cache_size ~tls cfg tcp udp primary
  in
  let@ () = fun () -> Resolver.kill daemon in
  compact ()

open Cmdliner

let features =
  let open Arg in
  let dnssec = info [ "dnssec" ] ~doc:"DNSSec validation" in
  let opportunistic_tls_authoritative =
    let doc = "Opportunistic encryption using TLS to the authoritative" in
    info [ "opportunistic-tls-authoritative" ] ~doc
  in
  let qname_minimisation =
    let doc = "Query name minimisation" in
    info [ "qname-minimisation" ] ~doc
  in
  let flags =
    [
      (`Dnssec, dnssec)
    ; (`Opportunistic_tls_authoritative, opportunistic_tls_authoritative)
    ; (`Qname_minimisation, qname_minimisation)
    ]
  in
  let defaults = [] in
  value & vflag_all defaults flags

let authenticator =
  let parser str =
    let* fn = X509.Authenticator.of_string str in
    Ok (fn, str)
  in
  let pp ppf (_fn, str) = Fmt.string ppf str in
  Arg.conv (parser, pp)

let authenticator =
  let doc = "X.509 authenticator to validate TLS certificates." in
  let open Arg in
  value
  & opt (some authenticator) None
  & info [ "a"; "authenticator" ] ~doc ~docv:"AUTHENTICATOR"

(* Lenient opportunistic authenticator.

   Authoritative DNS servers seldom present certificates issued by public
   PKI; strict validation against the NSS bundle would force a downgrade to
   plaintext on virtually every connection, defeating opportunistic privacy
   (see RFC 9539, "Unilateral Opportunistic Use of DoT for Recursive-to-
   Authoritative DNS"). On the other hand, blind acceptance discards useful
   information. This wrapper tries strict PKI validation, accepts the chain
   either way, and logs the outcome so anomalies (sudden issuer change,
   newly invalid chain) are observable. *)
let lenient_authenticator strict =
  let src = Logs.Src.create "pagejaune.authenticator" in
  let module Log = (val Logs.src_log src : Logs.LOG) in
  let pp_chain ppf certs =
    let pp_subject ppf cert =
      let subject = X509.Certificate.subject cert in
      X509.Distinguished_name.pp ppf subject
    in
    Fmt.list ~sep:Fmt.sp pp_subject ppf certs
  in
  fun ?ip ~host certs ->
    match strict ?ip ~host certs with
    | Ok _ as value ->
        Log.info (fun m ->
            m "Authoritative cert validated against PKI: %a" pp_chain certs);
        value
    | Error err ->
        Log.warn (fun m ->
            m "Authoritative cert NOT validated (%a); accepting anyway: %a"
              X509.Validation.pp_validation_error err pp_chain certs);
        Ok None

let setup_authenticator features = function
  | Some (fn, _) -> fn (Fun.compose Option.some Mirage_ptime.now)
  | None ->
      let opportunistic = List.mem `Opportunistic_tls_authoritative features in
      let nss = Result.get_ok (Ca_certs_nss.authenticator ()) in
      if opportunistic then lenient_authenticator nss else nss

let setup_authenticator =
  let open Term in
  const setup_authenticator $ features $ authenticator

let domain =
  let local = Domain_name.of_string_exn "local" in
  let is_valid subdomain =
    Domain_name.is_subdomain ~subdomain ~domain:local
    && Domain_name.count_labels subdomain >= 2
  in
  let parser str =
    let* domain_name = Domain_name.of_string str in
    let* domain_name = Domain_name.host domain_name in
    let* () =
      let err =
        msgf "Invalid domain %a: must end with .local (e.g. foo.local)"
          Domain_name.pp domain_name
      in
      guard ~err @@ fun () -> is_valid domain_name
    in
    Ok domain_name
  in
  let pp = Domain_name.pp in
  Arg.conv (parser, pp)

let domain =
  let doc =
    "Domain name advertised by the unikernel for DNS-over-TLS (e.g. \
     pageblanche.local). The certificate's SAN, the A record and the TLSA \
     record at _853._tcp.<domain> all use this name."
  in
  let open Arg in
  required & opt (some domain) None & info [ "domain" ] ~doc ~docv:"DOMAIN"

let duration =
  let parser = Duration.of_string in
  let pp = Duration.pp in
  Arg.conv (parser, pp)

let lifetime =
  let doc = "Validity period of the self-signed TLS certificate." in
  let open Arg in
  value
  & opt duration (Duration.of_day 365)
  & info [ "tls-lifetime" ] ~doc ~docv:"DURATION"

let seed =
  let parser str = Base64.decode str in
  let pp = Fmt.(using Base64.encode_string string) in
  Arg.conv (parser, pp)

let seed =
  let doc =
    "The seed to generate the private key for our TLS certificate (base64 \
     encoded)."
  in
  let open Arg in
  required & opt (some seed) None & info [ "seed" ] ~doc ~docv:"SEED"

let cache_size =
  let doc = "The size of the DNS cache." in
  let parser str =
    match int_of_string_opt str with
    | Some n when n <= 0 -> error_msgf "Invalid cache-size (negative number)"
    | Some n -> Ok n
    | None -> error_msgf "Invalid number: %S" str
  in
  let positive = Arg.conv (parser, Fmt.int) in
  let open Arg in
  value & opt positive 10_0000 & info [ "cache-size" ] ~doc ~docv:"NUMBER"

let term =
  let open Term in
  const run
  $ Mnet_cli.setup_logs
  $ Mnet_cli.setup "service"
  $ cache_size
  $ features
  $ setup_authenticator
  $ domain
  $ lifetime
  $ seed

let cmd =
  let info = Cmd.info "pagejaune" in
  Cmd.v info term

let () = Cmd.(exit @@ eval cmd)
