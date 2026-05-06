let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt
let guard ~err fn = if fn () then Ok () else Error err
let ( let@ ) finally fn = Fun.protect ~finally fn
let ( let* ) = Result.bind

let run (ipaddr, port) domain seed =
  Miou_unix.run ~domains:0 @@ fun () ->
  let rng = Mirage_crypto_rng_miou_unix.(initialize (module Pfortuna)) in
  let@ () = fun () -> Mirage_crypto_rng_miou_unix.kill rng in
  let hed, he = Happy_eyeballs_miou_unix.create () in
  let@ () = fun () -> Happy_eyeballs_miou_unix.kill hed in
  let nameservers = (`Udp, [ `Plaintext (ipaddr, port) ]) in
  let dns = Dns_client_miou_unix.create ~nameservers he in
  let _gen = Domain_name.prepend_label_exn domain "_gen" in
  match Dns_client_miou_unix.get_resource_record dns Dns.Rr_map.Txt _gen with
  | Ok (_ttl, gens) ->
      let gens = Dns.Rr_map.Txt_set.to_list gens in
      let gens = List.filter_map int_of_string_opt gens in
      let gens = List.sort (fun a b -> a - b) gens in
      if List.length gens > 0 then begin
        let count = List.hd gens in
        let { Dns.Tlsa.data; _ } = CA.regenerate ~count ~seed in
        Fmt.pr "%s\n%!" (Base64.encode_string data);
        Ok ()
      end
      else
        error_msgf "No _gen record published by the given DNS resolver %a (%a)"
          Domain_name.pp domain Ipaddr.pp ipaddr
  | Error (`Msg _) as err -> err
  | Error _ ->
      error_msgf "No _gen record published by the given resolver %a (%a)"
        Domain_name.pp domain Ipaddr.pp ipaddr

open Cmdliner

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
  let doc = "Domain name of the DNS resolver." in
  let open Arg in
  required & opt (some domain) None & info [ "domain" ] ~doc ~docv:"DOMAIN"

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

let ipaddr =
  let parser = Ipaddr.with_port_of_string ~default:53 in
  let pp ppf (ipaddr, port) = Fmt.pf ppf "%a:%d" Ipaddr.pp ipaddr port in
  Arg.conv (parser, pp)

let ipaddr =
  let doc = "The IP address of the DNS resolver." in
  let open Arg in
  required & pos 0 (some ipaddr) None & info [] ~doc ~docv:"IPADDR[:PORT]"

let term =
  let open Term in
  const run $ ipaddr $ domain $ seed |> term_result ~usage:false

let cmd =
  let info = Cmd.info "gen" in
  Cmd.v info term

let () = Cmd.(exit @@ eval cmd)
