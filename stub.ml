let src = Logs.Src.create "pageblanche.stub"

module Log = (val Logs.src_log src : Logs.LOG)

let _2s = 2_000_000_000

type io_addr =
  [ `Plaintext of Ipaddr.t * int | `Tls of Tls.Config.client * Ipaddr.t * int ]

type cfg = {
    cache_size: int option
  ; edns: [ `Auto | `Manual of Dns.Edns.t | `None ] option
  ; timeout: int64 option
  ; port: int
  ; secure_port: int
}

let config ?cache_size ?edns ?timeout ?(secure_port = 853) port =
  { cache_size; edns; timeout; port; secure_port }

exception Timeout

let with_timeout ~timeout fn =
  let prm0 = Miou.async @@ fun () -> Mkernel.sleep timeout; raise Timeout in
  let prm1 = Miou.async fn in
  match Miou.await_first [ prm0; prm1 ] with
  | Error Timeout -> Error `Timeout
  | Ok v -> Ok v
  | Error exn -> Error (`Exn exn)

let rec clean_up orphans =
  match Miou.care orphans with
  | Some None | None -> ()
  | Some (Some prm) ->
      begin match Miou.await prm with
      | Ok () -> clean_up orphans
      | Error exn ->
          Log.debug (fun m ->
              m "per-connection task ended with %s" (Printexc.to_string exn));
          clean_up orphans
      end

type t = {
    mutex: Miou.Mutex.t
  ; mutable server: Dns_server.t
  ; clients: Mnet_dns.t list
  ; ban: Mkernel.Block.t Cachet.t
}

let with_tcp t ~handler tcp port =
  let rec go orphans listen =
    clean_up orphans;
    let flow = Mnet.TCP.accept tcp listen in
    let _ =
      Miou.async ~orphans @@ fun () ->
      let _, (dst, _) = Mnet.TCP.peers flow in
      let finally = Mnet.TCP.close in
      let res = Miou.Ownership.create ~finally flow in
      Miou.Ownership.own res;
      let rec go () =
        let len = Bytes.create 2 in
        Mnet.TCP.really_read flow len;
        let len = Bytes.get_uint16_be len 0 in
        let buf = Bytes.create len in
        Mnet.TCP.really_read flow buf;
        match handler t `Tcp dst (Bytes.unsafe_to_string buf) with
        | None -> go ()
        | Some (_ttl, str) ->
            let len = Bytes.create 2 in
            Bytes.set_uint16_be len 0 (String.length str);
            let len = Bytes.unsafe_to_string len in
            Mnet.TCP.write flow len; Mnet.TCP.write flow str; go ()
      in
      go ()
    in
    go orphans listen
  in
  go (Miou.orphans ()) (Mnet.TCP.listen tcp port)

let with_udp t ~handler udp port =
  let rec go () =
    let buf = Bytes.create 4096 in
    let len, (peer, pport) = Mnet.UDP.recvfrom udp ~port buf in
    let str = Bytes.sub_string buf 0 len in
    match handler t `Udp peer str with
    | None -> go ()
    | Some (_ttl, str) ->
        let on_error err =
          Log.warn (fun m ->
              m "Failure while sending to %a:%d: %a" Ipaddr.pp peer pport
                Mnet.UDP.pp_error err)
        in
        let result =
          Mnet.UDP.sendto udp ~dst:peer ~src_port:port ~port:pport str
        in
        Result.iter_error on_error result;
        go ()
  in
  go ()

let with_tls t tls ~handler tcp port =
  let rec go orphans listen =
    clean_up orphans;
    let flow = Mnet.TCP.accept tcp listen in
    let _ =
      Miou.async ~orphans @@ fun () ->
      let _, (dst, dport) = Mnet.TCP.peers flow in
      let finally = Mnet.TCP.close in
      let res0 = Miou.Ownership.create ~finally flow in
      Miou.Ownership.own res0;
      let cfg = MTLS.tls tls in
      let fn () = Mnet_tls.server_of_fd cfg flow in
      match with_timeout ~timeout:_2s fn with
      | Error (`Timeout | `Exn _) ->
          Log.warn (fun m ->
              m "TLS handshake failed with %a:%d" Ipaddr.pp dst dport);
          Miou.Ownership.release res0
      | Ok tls ->
          let finally = Mnet_tls.close in
          let res1 = Miou.Ownership.create ~finally tls in
          Miou.Ownership.disown res0;
          Miou.Ownership.own res1;
          let rec go () =
            let len = Bytes.create 2 in
            Mnet_tls.really_read tls len;
            let len = Bytes.get_uint16_be len 0 in
            let buf = Bytes.create len in
            Mnet_tls.really_read tls buf;
            match handler t `Tcp dst (Bytes.unsafe_to_string buf) with
            | None -> go ()
            | Some (_ttl, str) ->
                let len = Bytes.create 2 in
                Bytes.set_uint16_be len 0 (String.length str);
                let len = Bytes.unsafe_to_string len in
                Mnet_tls.write tls len; Mnet_tls.write tls str; go ()
          in
          go ()
    in
    go orphans listen
  in
  go (Miou.orphans ()) (Mnet.TCP.listen tcp port)

let reply hdr question proto ?additional data =
  let ttl = Dns.Packet.minimum_ttl data in
  let pkt = Dns.Packet.create ?additional hdr question data in
  (ttl, fst (Dns.Packet.encode proto pkt))

let query trie question data hdr proto =
  match Dns_server.handle_question trie question with
  | Error (Dns.Rcode.NotAuth, _) -> None
  | Error (rcode, answer) ->
      let opcode = Dns.Packet.opcode_data data in
      let data = `Rcode_error (rcode, opcode, answer) in
      let reply = reply hdr question proto data in
      Some (reply, rcode)
  | Ok (_flags (* TODO *), answer, additional) ->
      let data = `Answer answer in
      let ttl = Dns.Packet.minimum_ttl data in
      let pkt = Dns.Packet.create ?additional hdr question data in
      let pkt =
        match Dns_block.edns pkt with
        | None -> pkt
        | Some edns -> Dns.Packet.with_edns pkt (Some edns)
      in
      let reply = (ttl, fst (Dns.Packet.encode proto pkt)) in
      Some (reply, Dns.Packet.rcode_data data)

let tsig_decode_sign server proto pkt str hdr question =
  let now = Mirage_ptime.now () in
  match Dns_server.handle_tsig server now pkt str with
  | Error _ ->
      let opcode = Dns.Packet.opcode_data pkt.Dns.Packet.data in
      let data = `Rcode_error (Dns.Rcode.Refused, opcode, None) in
      let reply = reply hdr question proto data in
      Error (reply, Dns.Rcode.Refused)
  | Ok key ->
      let sign data =
        let ttl = Dns.Packet.minimum_ttl data in
        let pkt = Dns.Packet.create hdr question data in
        match key with
        | None ->
            let rcode = Dns.Packet.rcode_data data in
            Some ((ttl, fst (Dns.Packet.encode proto pkt)), rcode)
        | Some (name, _tsig, mac, key) ->
            let result =
              Dns_tsig.encode_and_sign ~proto ~mac pkt now key name
            in
            let fn (str, _) = ((ttl, str), Dns.Packet.rcode_data data) in
            let result = Result.map fn result in
            let on_error err =
              Log.err (fun m ->
                  m "Error %a while signing answer" Dns_tsig.pp_s err)
            in
            Result.iter_error on_error result;
            Result.to_option result
      in
      let fn (name, _, _, _) = name in
      let key = Option.map fn key in
      Ok (key, sign)

let axfr server proto pkt question str hdr =
  match tsig_decode_sign server proto pkt str hdr question with
  | Error err -> Some err
  | Ok (key, sign) ->
      begin match Dns_server.handle_axfr_request server proto key question with
      | Error rcode ->
          let opcode = Dns.Packet.opcode_data pkt.Dns.Packet.data in
          let err = `Rcode_error (rcode, opcode, None) in
          let reply = reply hdr question proto err in
          Some (reply, rcode)
      | Ok axfr -> sign (`Axfr_reply axfr)
      end

let update t proto _ipaddr pkt question u str hdr =
  Miou.Mutex.protect t.mutex @@ fun () ->
  let server = t.server in
  match tsig_decode_sign server proto pkt str hdr question with
  | Error err -> Some err
  | Ok (key, sign) ->
      begin match Dns_server.handle_update server proto key question u with
      | Ok (trie, _) ->
          let server = Dns_server.with_data server trie in
          t.server <- server;
          sign `Update_ack
      | Error rcode ->
          let err = `Rcode_error (rcode, Dns.Opcode.Update, None) in
          sign err
      end

let server t proto ipaddr pkt hdr question data str =
  match data with
  | `Query -> query t.server question data hdr proto
  | `Axfr_request -> axfr t.server proto pkt question str hdr
  | `Update u -> update t proto ipaddr pkt question u str hdr
  | _ ->
      let opcode = Dns.Packet.opcode_data pkt.Dns.Packet.data in
      let data = `Rcode_error (Dns.Rcode.NotImp, opcode, None) in
      let pkt = reply hdr question proto data in
      Some (pkt, Dns.Rcode.NotImp)

let _5ms = 500_000_000

let pp_nameservers ppf (proto, nameservers) =
  match (proto, nameservers) with
  | `Tcp, `Tls (_, ipaddr, port) :: _ ->
      Fmt.pf ppf "tls://%a:%d" Ipaddr.pp ipaddr port
  | `Tcp, `Plaintext (ipaddr, port) :: _ ->
      Fmt.pf ppf "tcp://%a:%d" Ipaddr.pp ipaddr port
  | `Udp, `Plaintext (ipaddr, port) :: _ ->
      Fmt.pf ppf "udp://%a:%d" Ipaddr.pp ipaddr port
  | _ -> assert false

let race clients key name =
  let cancel orphans =
    let prms = Seq.of_dispenser (fun () -> Miou.take orphans) in
    let prms = List.of_seq prms in
    List.iter Miou.cancel prms
  in
  let rec clean_up orphans =
    match Miou.care orphans with
    | None | Some None -> None
    | Some (Some prm) ->
        begin match Miou.await prm with
        | Error _exn -> clean_up orphans
        | Ok (Error (`Msg _)) -> clean_up orphans
        | Ok data -> Some data
        end
  in
  let rec terminate orphans =
    match Miou.care orphans with
    | None -> None
    | Some None -> Mkernel.sleep _5ms; terminate orphans
    | Some (Some prm) ->
        begin match Miou.await prm with
        | Error _exn -> terminate orphans
        | Ok (Error (`Msg _)) -> terminate orphans
        | Ok data ->
            Log.debug (fun m ->
                m "Got a new response, cancel other resolver(s)");
            cancel orphans;
            Some data
        end
  in
  let rec go orphans clients =
    match (clean_up orphans, clients) with
    | None, [] ->
        Log.debug (fun m -> m "Waiting our resolver(s)");
        terminate orphans
    | None, client :: clients ->
        Log.debug (fun m ->
            m "Trying with %a" pp_nameservers (Mnet_dns.nameservers client));
        let prm0 =
          Miou.async ~orphans @@ fun () ->
          Mnet_dns.get_resource_record client key name
        in
        let prm1 =
          Miou.async ~orphans @@ fun () -> Mkernel.sleep _5ms; raise Timeout
        in
        begin match Miou.await_one [ prm0; prm1 ] with
        | Error _exn ->
            Log.debug (fun m -> m "Try with the next nameserver");
            go orphans clients
        | Ok (Error (`Msg _)) ->
            Log.debug (fun m -> m "Try with the next nameserver");
            go orphans clients
        | Ok data -> cancel orphans; Some data
        end
    | Some data, _ -> cancel orphans; Some data
  in
  go (Miou.orphans ()) clients

let resolve t question data hdr proto =
  let name = fst question in
  match (data, snd question) with
  | `Query, `K (Dns.Rr_map.K key) ->
      begin match race t.clients key name with
      | None | Some (Error (`Msg _)) ->
          let data = `Rcode_error Dns.(Rcode.ServFail, Opcode.Query, None) in
          let reply = reply hdr question proto data in
          Some (reply, Dns.Rcode.ServFail)
      | Some (Error (`No_data (domain, soa))) ->
          let answer =
            let open Dns.Name_rr_map in
            (empty, singleton domain Soa soa)
          in
          let data = `Answer answer in
          let reply = reply hdr question proto data in
          Some (reply, Dns.Rcode.NoError)
      | Some (Error (`No_domain (domain, soa))) ->
          let answer =
            let open Dns.Name_rr_map in
            (empty, singleton domain Soa soa)
          in
          let rcode = Dns.Rcode.NXDomain in
          let data = `Rcode_error (rcode, Dns.Opcode.Query, Some answer) in
          let reply = reply hdr question proto data in
          Some (reply, Dns.Rcode.NXDomain)
      | Some (Ok value) ->
          let answer =
            let open Dns.Name_rr_map in
            (singleton name key value, empty)
          in
          let data = `Answer answer in
          let reply = reply hdr question proto data in
          Some (reply, Dns.Rcode.NoError)
      end
  | _ ->
      Log.err (fun m ->
          m "Not implemented %a, data %a" Dns.Packet.Question.pp question
            Dns.Packet.pp_data data);
      let opcode = Dns.Packet.opcode_data data in
      let data = `Rcode_error (Dns.Rcode.NotImp, opcode, None) in
      let reply = reply hdr question proto data in
      Some (reply, Dns.Rcode.NotImp)

let blocked_reply hdr question proto =
  let name = fst question in
  let soa = Dns.Soa.create name in
  let answer =
    let open Dns.Name_rr_map in
    (empty, singleton name Soa soa)
  in
  let data = `Rcode_error (Dns.Rcode.NXDomain, Dns.Opcode.Query, Some answer) in
  reply hdr question proto data

let handler t proto ipaddr str =
  match Dns.Packet.decode str with
  | Error err ->
      Log.err (fun m -> m "Couldn't decode %a" Dns.Packet.pp_err err);
      let answer = Dns.Packet.raw_error str Dns.Rcode.FormErr in
      Option.map (fun r -> (0l, r)) answer
  | Ok pkt ->
      let hdr = pkt.Dns.Packet.header
      and question = pkt.Dns.Packet.question
      and data = pkt.Dns.Packet.data in
      let name = fst question in
      let reply =
        match data with
        | `Query when Trie.exists t.ban (Domain_name.to_string name) ->
            Log.info (fun m -> m "Blocked %a" Domain_name.pp name);
            Some (blocked_reply hdr question proto, Dns.Rcode.NXDomain)
        | _ ->
            begin match server t proto ipaddr pkt hdr question data str with
            | Some _ as value -> value
            | None -> resolve t question data hdr proto
            end
      in
      Option.map fst reply

type daemon = {
    tcp_server: unit Miou.t
  ; udp_server: unit Miou.t
  ; tls_server: unit Miou.t option
  ; crt_update: unit Miou.t option
}

let create cfg ?(with_reserved = true) ~ban ?tls tcp udp he nameservers =
  let rng = Mirage_crypto_rng.generate in
  let primary = Dns_server.Primary.create ~rng Dns_trie.empty in
  let primary =
    if with_reserved then
      let trie = Dns_server.Primary.data primary in
      let trie = Dns_trie.insert_map Dns_resolver_root.reserved_zones trie in
      let now = Mirage_ptime.now () in
      let mon = Int64.of_int (Mkernel.clock_monotonic ()) in
      let primary, _ = Dns_server.Primary.with_data primary now mon trie in
      primary
    else primary
  in
  let server = Dns_server.Primary.server primary in
  let mutex = Miou.Mutex.create () in
  let fn (proto, nameserver) =
    let cache_size = cfg.cache_size
    and edns = cfg.edns
    and timeout = cfg.timeout in
    Mnet_dns.create ?cache_size ?edns ?timeout
      ~nameservers:(proto, [ nameserver ]) (udp, he)
  in
  let clients = List.map fn nameservers in
  Logs.info (fun m -> m "Use %d nameserver(s)" (List.length clients));
  let t = { server; clients; mutex; ban } in
  let tcp_server = Miou.async @@ fun () -> with_tcp t ~handler tcp cfg.port in
  let udp_server = Miou.async @@ fun () -> with_udp t ~handler udp cfg.port in
  let tls_server, crt_update =
    let get () = t.server.Dns_server.data in
    let set trie = t.server <- Dns_server.with_data t.server trie in
    let fn = MTLS.create ~get ~set in
    let tls = Option.bind tls fn in
    match tls with
    | None -> (None, None)
    | Some (tls, prm0) ->
        let prm1 =
          Miou.async @@ fun () -> with_tls t tls ~handler tcp cfg.secure_port
        in
        (Some prm0, Some prm1)
  in
  let daemon = { tcp_server; udp_server; tls_server; crt_update } in
  (t, daemon)

let kill { tcp_server; udp_server; tls_server; crt_update } =
  Miou.cancel tcp_server;
  Miou.cancel udp_server;
  Option.iter Miou.cancel tls_server;
  Option.iter Miou.cancel crt_update
