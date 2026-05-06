let src = Logs.Src.create "annuaire.tls"

module Log = (val Logs.src_log src : Logs.LOG)

type t = {
    set: Dns_trie.t -> unit
  ; get: unit -> Dns_trie.t
  ; cfg: CA.cfg
  ; tls: Tls.Config.server Atomic.t
}

let tls { tls; _ } = Atomic.get tls

let span_to_ns span =
  let d, ps = Ptime.Span.to_d_ps span in
  let ns_per_d = 86_400 * 1_000_000_000 in
  (d * ns_per_d) + Int64.to_int (Int64.div ps 1_000L)

let _5s = Ptime.Span.of_int_s 5
let _10s = 10_000_000_000
let _1d = 86_400_000_000_000

let renewal_delay validity =
  let now = Mirage_ptime.now () in
  let target = Ptime.sub_span validity _5s in
  let target = Option.value ~default:validity target in
  let span = Ptime.diff target now in
  if Ptime.Span.compare span Ptime.Span.zero <= 0 then 0 else span_to_ns span

let publish ?counts t tlsa =
  let trie = t.get () in
  let trie = CA.with_tlsa_entries t.cfg tlsa trie in
  let trie = CA.with_gen ?counts t.cfg trie in
  t.set trie

let _1h = 3_600_000_000_000

(* NOTE(dinosaure): width of the [old, new] TLSA overlap.

   A [pageblanche] client refreshes its TLSA pin every [TTL/2]; for the
   refresh to reliably catch the overlap, the overlap must be wider than
   TTL/2. We pick [overlap = Int.min ttl_ns (lifetime_ns / 2)]: enough to cover
   one full refresh period, but never more than half the certificate's
   lifetime (otherwise we'd switch to [tls'] less than [validity - overlap]
   away from its expiry, and the next [renewal_delay] would fire almost
   immediately, melting the rotation cycle).

   We clamp to [[_10s, _1d]]: 10s is the original behaviour and a sane
   lower bound when [ttl] is misconfigured to 0; 1 day caps the overlap so
   we don't sleep excessively on long-lived certs (e.g. 365 d with the
   default 1 h TTL would otherwise yield 1 h, which is fine — the cap
   only kicks in for unusually large TTLs). *)
let overlap_ns t =
  let ttl_ns =
    Int64.to_int (Int64.mul (Int64.of_int32 (CA.ttl t.cfg)) 1_000_000_000L)
  in
  let lifetime_ns = span_to_ns (CA.lifetime t.cfg) in
  let overlap = Int.min ttl_ns (lifetime_ns / 2) in
  let overlap = Int.max overlap _10s in
  Int.min overlap _1d

let renew t tlsa until =
  let tlsa = ref tlsa in
  let count = ref (CA.count t.cfg) in
  let until = ref until in
  let rec go () =
    Log.debug (fun m ->
        m "certificate valid until: %a" (Ptime.pp_human ()) !until);
    let delay = renewal_delay !until in
    Log.debug (fun m -> m "wait %a" Duration.pp (Int64.of_int delay));
    if delay > 0 then Mkernel.sleep delay;
    Log.debug (fun m ->
        m "renewing TLS certificate for %a" Domain_name.pp (CA.domain t.cfg));
    match CA.generate t.cfg with
    | Error (`Msg msg) ->
        Log.err (fun m -> m "renewal failed (%s); retrying in 1h" msg);
        Mkernel.sleep _1h;
        go ()
    | Ok (tls', tlsa', until') ->
        let count' = CA.count t.cfg in
        publish ~counts:[ !count; count' ] t [ !tlsa; tlsa' ];
        (* NOTE(dinosaure): publish old and new TLSA (and matching counters)
           so that pageblanche can regenerate either fingerprint during the
           overlap window. *)
        let overlap = overlap_ns t in
        Log.debug (fun m ->
            m "published overlap TLSA set, waiting %a for caches" Duration.pp
              (Int64.of_int overlap));
        Mkernel.sleep overlap;
        Atomic.set t.tls tls';
        publish ~counts:[ count' ] t [ tlsa' ];
        tlsa := tlsa';
        count := count';
        until := until';
        Log.info (fun m ->
            m "TLS certificate renewed (valid until %a)" (Ptime.pp_human ())
              until');
        go ()
  in
  go ()

let create ~get ~set cfg =
  match CA.generate cfg with
  | Ok (tls, tlsa, until) ->
      let tls = Atomic.make tls in
      let t = { get; set; cfg; tls } in
      publish t [ tlsa ];
      let prm = Miou.async @@ fun () -> renew t tlsa until in
      Some (t, prm)
  | Error _ -> None
