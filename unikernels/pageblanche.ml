module RNG = Mirage_crypto_rng.Fortuna
module Stub = Stub

let _2s = 2_000_000_000
let ( let@ ) finally fn = Fun.protect ~finally fn
let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
let rng = Mkernel.map rng Mkernel.[]
let ( let* ) = Result.bind
let guard ~err fn = if fn () then Ok () else Error err
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt

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

let cachet ~name =
  let fn blk () =
    let pagesize = Mkernel.Block.sector_size blk in
    let map blk ~pos len =
      let bstr = Bstr.create len in
      Mkernel.Block.read blk ~src_off:pos bstr;
      bstr
    in
    Cachet.make ~pagesize ~map blk
  in
  Mkernel.(map fn [ block name ])

let first_cidrv4 lst =
  let fn = function Ipaddr.V4 _ -> true | _ -> false in
  List.find fn lst |> function Ipaddr.V4 cidrv4 -> cidrv4 | _ -> assert false

let run _ stack recursive nameservers happy_eyeballs domain lifetime seed =
  Mkernel.run [ rng; stack; cachet ~name:"ban" ]
  @@ fun rng (daemon, tcp, udp) ban () ->
  let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
  let@ () = fun () -> Mnet.kill daemon in
  let hed, he = Mnet_happy_eyeballs.create ~happy_eyeballs tcp in
  let@ () = fun () -> Mnet_happy_eyeballs.kill hed in
  let cfg = Stub.config 53 in
  let tls =
    let addresses = Mnet.addresses daemon in
    let ipaddr = Ipaddr.V4.Prefix.address (first_cidrv4 addresses) in
    let lifetime = Ptime.Span.of_int_s (Duration.to_sec lifetime) in
    CA.cfg ~lifetime ~seed ipaddr domain
  in
  let nameservers, refresher =
    let fn (ipaddr, host, seed) =
      Pin.launch udp he ipaddr host seed |> Result.to_option
    in
    match Option.bind recursive fn with
    | Some (tls, prm) -> (tls :: nameservers, Some prm)
    | None -> (nameservers, None)
  in
  let@ () = fun () -> Option.iter Miou.cancel refresher in
  let _stub, daemon = Stub.create cfg ~ban ~tls tcp udp he nameservers in
  let@ () = fun () -> Stub.kill daemon in
  compact ()

open Cmdliner

let setup_happy_eyeballs
    {
      Mnet_happy_eyeballs_cli.aaaa_timeout
    ; connect_delay
    ; connect_timeout
    ; resolve_timeout
    ; resolve_retries
    } =
  let now = Mkernel.clock_monotonic () in
  let now = Int64.of_int now in
  Happy_eyeballs.create ~aaaa_timeout ~connect_delay ~connect_timeout
    ~resolve_timeout ~resolve_retries now

let setup_happy_eyeballs =
  let open Term in
  const setup_happy_eyeballs $ Mnet_happy_eyeballs_cli.setup

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
     foo.local). The certificate's SAN, the A record and the TLSA record at \
     _853._tcp.<domain> all use this name."
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

let recursive =
  let parser str =
    match String.split_on_char '!' str with
    | [ ipaddr; host; seed ] ->
        let* ipaddr = Ipaddr.of_string ipaddr in
        let* dn = Domain_name.of_string host in
        let* dn = Domain_name.host dn in
        let* seed = Base64.decode seed in
        Ok (ipaddr, dn, seed)
    | _ -> error_msgf "Expected <ip>!<host>!<seed-base64>, got %S" str
  in
  let pp ppf (ipaddr, host, seed) =
    Fmt.pf ppf "%a!%a!%s" Ipaddr.pp ipaddr Domain_name.pp host
      (Base64.encode_string seed)
  in
  Arg.conv (parser, pp)

let recursive =
  let doc =
    "Upstream pagejaune endpoint as $(b,<ip>[:<port>]!<host>!<seed-base64>). \
     When set, $(cmd) forwards every recursive query over DoT to this \
     endpoint. The base64 $(b,seed) must match the one used by pagejaune to \
     derive its TLS keypair: $(cmd) reads the counter published at \
     $(b,_gen.<host>) (TXT) and regenerates pagejaune's expected SPKI \
     fingerprint locally instead of trusting any TLSA record received in \
     cleartext. The pin set is then refreshed by re-querying that counter over \
     the established DoT channel."
  in
  let open Arg in
  value & opt (some recursive) None & info [ "pagejaune" ] ~doc ~docv:"ENDPOINT"

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

let term =
  let open Term in
  const run
  $ Mnet_cli.setup_logs
  $ Mnet_cli.setup "service"
  $ recursive
  $ Mnet_dns_cli.nameservers ()
  $ setup_happy_eyeballs
  $ domain
  $ lifetime
  $ seed

let cmd =
  let info = Cmd.info "pageblanche" in
  Cmd.v info term

let () = Cmd.(exit @@ eval cmd)
