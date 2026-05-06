module RNG = Mirage_crypto_rng.Fortuna

let _2s = 2_000_000_000
let ( let@ ) finally fn = Fun.protect ~finally fn
let rec forever () = Mkernel.sleep _2s; Gc.compact (); forever ()
let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
let rng = Mkernel.map rng Mkernel.[]
let ( let* ) = Result.bind
let guard ~err fn = if fn () then Ok () else Error err
let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt

let run _ (cidr, gateway, ipv6) cache_size features authenticator domain
    lifetime seed =
  Mkernel.(run [ rng; Mnet.stack ~name:"service" ?gateway ~ipv6 cidr ])
  @@ fun rng (daemon, tcp, udp) () ->
  let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
  let@ () = fun () -> Mnet.kill daemon in
  let rng = Mirage_crypto_rng.generate in
  let root = Dns_resolver_shared.Root.reserved in
  let primary = Dns_server.Primary.create ~rng root in
  let tls =
    let ipaddr = Ipaddr.V4.Prefix.address cidr in
    let lifetime = Ptime.Span.of_int_s (Duration.to_sec lifetime) in
    CA.cfg ~lifetime ~seed ipaddr domain
  in
  let cfg = Tls.Config.client ~authenticator () in
  let cfg = Result.get_ok cfg in
  let _resolver, daemon =
    Resolver.create ~features ~cache_size ~tls cfg tcp udp primary
  in
  let@ () = fun () -> Resolver.kill daemon in
  forever ()

open Cmdliner

let output_options = "OUTPUT OPTIONS"
let verbosity = Logs_cli.level ~docs:output_options ()
let renderer = Fmt_cli.style_renderer ~docs:output_options ()

let utf_8 =
  let doc = "Allow binaries to emit UTF-8 characters." in
  Arg.(value & opt bool true & info [ "with-utf-8" ] ~doc)

let t0 = Mkernel.clock_monotonic ()
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let neg fn = fun x -> not (fn x)

let reporter sources ppf =
  let re = Option.map Re.compile sources in
  let print src =
    let some re = (neg List.is_empty) (Re.matches re (Logs.Src.name src)) in
    Option.fold ~none:true ~some re
  in
  let report src level ~over k msgf =
    let k _ = over (); k () in
    let pp header _tags k ppf fmt =
      let t1 = Mkernel.clock_monotonic () in
      let delta = Float.of_int (t1 - t0) in
      let delta = delta /. 1_000_000_000. in
      Fmt.kpf k ppf
        ("[+%a][%a]%a[%a]: " ^^ fmt ^^ "\n%!")
        Fmt.(styled `Blue (fmt "%04.04f"))
        delta
        Fmt.(styled `Cyan int)
        (Stdlib.Domain.self () :> int)
        Logs_fmt.pp_header (level, header)
        Fmt.(styled `Magenta string)
        (Logs.Src.name src)
    in
    match (level, print src) with
    | Logs.Debug, false -> k ()
    | _, true | _ -> msgf @@ fun ?header ?tags fmt -> pp header tags k ppf fmt
  in
  { Logs.report }

let regexp =
  let parser str =
    match Re.Pcre.re str with
    | re -> Ok (str, `Re re)
    | exception _ -> error_msgf "Invalid PCRegexp: %S" str
  in
  let pp ppf (str, _) = Fmt.string ppf str in
  Arg.conv (parser, pp)

let sources =
  let doc = "A regexp (PCRE syntax) to identify which log we print." in
  let open Arg in
  value & opt_all regexp [ ("", `None) ] & info [ "l" ] ~doc ~docv:"REGEXP"

let setup_sources = function
  | [ (_, `None) ] -> None
  | res ->
      let res = List.map snd res in
      let fn acc = function `Re re -> re :: acc | _ -> acc in
      let res = List.fold_left fn [] res in
      Some (Re.alt res)

let setup_sources = Term.(const setup_sources $ sources)

let setup_logs utf_8 style_renderer sources level =
  Option.iter (Fmt.set_style_renderer Fmt.stdout) style_renderer;
  Fmt.set_utf_8 Fmt.stdout utf_8;
  Logs.set_level level;
  Logs.set_reporter (reporter sources Fmt.stdout);
  Option.is_none level

let setup_logs =
  let open Term in
  const setup_logs $ utf_8 $ renderer $ setup_sources $ verbosity

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
  $ setup_logs
  $ Mnet_cli.setup
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
