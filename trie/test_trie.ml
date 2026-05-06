let test name fn =
  try
    fn ();
    Printf.printf "PASS: %s\n" name
  with exn ->
    Printf.printf "FAIL: %s (%s)\n" name (Printexc.to_string exn);
    exit 1

let () =
  test "insert and find single key" @@ fun () ->
  let t = Trie.create () in
  Trie.insert t "hello" 42;
  assert (Trie.find t "hello" = 42)

let () =
  test "find raises Not_found on missing key" @@ fun () ->
  let t = Trie.create () in
  Trie.insert t "hello" 1;
  try
    ignore (Trie.find t "world");
    assert false
  with Not_found -> ()

let () =
  test "find raises Not_found on empty trie" @@ fun () ->
  let t = Trie.create () in
  try
    ignore (Trie.find t "any");
    assert false
  with Not_found -> ()

let () =
  test "insert overwrites existing key" @@ fun () ->
  let t = Trie.create () in
  Trie.insert t "key" 1;
  Trie.insert t "key" 2;
  assert (Trie.find t "key" = 2)

let () =
  test "multiple distinct keys" @@ fun () ->
  let t = Trie.create () in
  Trie.insert t "alpha" 1;
  Trie.insert t "beta" 2;
  Trie.insert t "gamma" 3;
  assert (Trie.find t "alpha" = 1);
  assert (Trie.find t "beta" = 2);
  assert (Trie.find t "gamma" = 3)

let () =
  test "keys sharing a common prefix" @@ fun () ->
  let t = Trie.create () in
  Trie.insert t "abc" 1;
  Trie.insert t "abd" 2;
  Trie.insert t "xyz" 3;
  assert (Trie.find t "abc" = 1);
  assert (Trie.find t "abd" = 2);
  assert (Trie.find t "xyz" = 3)

let () =
  test "key is prefix of another key" @@ fun () ->
  let t = Trie.create () in
  Trie.insert t "log" 1;
  Trie.insert t "login" 2;
  assert (Trie.find t "log" = 1);
  assert (Trie.find t "login" = 2)

let () =
  test "longer key inserted first, shorter second" @@ fun () ->
  let t = Trie.create () in
  Trie.insert t "login" 2;
  Trie.insert t "log" 1;
  assert (Trie.find t "log" = 1);
  assert (Trie.find t "login" = 2)

let () =
  test "single character keys" @@ fun () ->
  let t = Trie.create () in
  Trie.insert t "a" 1;
  Trie.insert t "b" 2;
  assert (Trie.find t "a" = 1);
  assert (Trie.find t "b" = 2)

let () =
  test "iter visits all entries" @@ fun () ->
  let t = Trie.create () in
  Trie.insert t "foo" 10;
  Trie.insert t "bar" 20;
  Trie.insert t "baz" 30;
  let acc = ref [] in
  Trie.iter (fun k v -> acc := (k, v) :: !acc) t;
  let sorted = List.sort (fun (a, _) (b, _) -> String.compare a b) !acc in
  assert (sorted = [ ("bar", 20); ("baz", 30); ("foo", 10) ])

let float_to_string flt =
  let tmp = Bytes.create 8 in
  let flt = Int64.bits_of_float flt in
  Bytes.set_int64_le tmp 0 flt;
  Bytes.unsafe_to_string tmp

let () =
  test "serialize and check file is page-aligned" @@ fun () ->
  let t = Trie.create () in
  Trie.insert t "hello" 1.0;
  Trie.insert t "world" 2.0;
  let tmp = Filename.temp_file "trie" ".bin" in
  let oc = open_out_bin tmp in
  Trie.serialize float_to_string oc ~pagesize:4096 t;
  close_out oc;
  let st = Unix.stat tmp in
  assert (st.Unix.st_size mod 4096 = 0);
  Sys.remove tmp

let () =
  test "serialize with many keys produces page-aligned file" @@ fun () ->
  let t = Trie.create () in
  for i = 0 to 99 do
    Trie.insert t (Fmt.str "key_%03d" i) (Float.of_int i)
  done;
  let tmp = Filename.temp_file "trie" ".bin" in
  let oc = open_out_bin tmp in
  Trie.serialize float_to_string oc ~pagesize:4096 t;
  close_out oc;
  let st = Unix.stat tmp in
  assert (st.Unix.st_size mod 4096 = 0);
  Sys.remove tmp

let pagesize = 4096

let cachet_of_file filename =
  let fd = Unix.openfile filename Unix.[ O_RDONLY ] 0o644 in
  let { Unix.st_size; _ } = Unix.fstat fd in
  let map (fd, max) ~pos len =
    let len = Int.min (max - pos) len in
    let pos = Int64.of_int pos in
    let open Bigarray in
    let barr = Unix.map_file fd ~pos char c_layout false [| len |] in
    array1_of_genarray barr
  in
  let cache = Cachet.make ~pagesize ~map (fd, st_size) in
  (cache, fd)

let float_of_string str =
  let flt = String.get_int64_le str 0 in
  Int64.float_of_bits flt

let serialize_and_lookup t (of_string, to_string) keys =
  let tmp = Filename.temp_file "trie" ".bin" in
  let oc = open_out_bin tmp in
  Trie.serialize to_string oc ~pagesize t;
  close_out oc;
  let cache, fd = cachet_of_file tmp in
  let finally () =
    Unix.close fd;
    Sys.remove tmp
  in
  Fun.protect ~finally @@ fun () ->
  let fn (key, expected) =
    match Trie.lookup cache of_string key with
    | Some value -> assert (value = expected)
    | None -> Fmt.failwith "%s not found" key
  in
  List.iter fn keys

let () =
  test "lookup single key from serialized trie" @@ fun () ->
  let t = Trie.create () in
  Trie.insert t "hello" 3.14;
  serialize_and_lookup t (float_of_string, float_to_string) [ ("hello", 3.14) ]

let () =
  test "lookup multiple keys from serialized trie" @@ fun () ->
  let t = Trie.create () in
  Trie.insert t "alpha" 1.0;
  Trie.insert t "beta" 2.0;
  Trie.insert t "gamma" 3.0;
  serialize_and_lookup t
    (float_of_string, float_to_string)
    [ ("alpha", 1.0); ("beta", 2.0); ("gamma", 3.0) ]

let () =
  test "lookup with shared prefixes from serialized trie" @@ fun () ->
  let t = Trie.create () in
  Trie.insert t "log" 1.0;
  Trie.insert t "login" 2.0;
  Trie.insert t "logging" 3.0;
  serialize_and_lookup t
    (float_of_string, float_to_string)
    [ ("log", 1.0); ("login", 2.0); ("logging", 3.0) ]

let () =
  test "lookup raises Not_found for missing key in serialized trie" @@ fun () ->
  let t = Trie.create () in
  Trie.insert t "hello" 42.0;
  let tmp = Filename.temp_file "trie" ".bin" in
  let oc = open_out_bin tmp in
  Trie.serialize float_to_string oc ~pagesize t;
  close_out oc;
  let cache, fd = cachet_of_file tmp in
  let finally () =
    Unix.close fd;
    Sys.remove tmp
  in
  Fun.protect ~finally @@ fun () ->
  match Trie.lookup cache float_of_string "world" with
  | Some _ -> assert false
  | None -> ()

let () =
  test "lookup many keys from serialized trie" @@ fun () ->
  let t = Trie.create () in
  let keys =
    List.init 100 (fun i ->
        let key = Printf.sprintf "token_%03d" i in
        let value = Float.of_int i *. 0.1 in
        Trie.insert t key value;
        (key, value))
  in
  serialize_and_lookup t (float_of_string, float_to_string) keys

(* Test with postings format identical to precompute/main *)

let output_int32_le =
  let tmp = Bytes.create 4 in
  fun buf value ->
    Bytes.set_int32_le tmp 0 (Int32.of_int value);
    Buffer.add_bytes buf tmp

let output_float_le =
  let tmp = Bytes.create 8 in
  fun buf flt ->
    let flt = Int64.bits_of_float flt in
    Bytes.set_int64_le tmp 0 flt;
    Buffer.add_bytes buf tmp

let to_string entries =
  let buf = Buffer.create 0x7ff in
  output_int32_le buf (List.length entries);
  let fn (uid, freq, length) =
    Buffer.add_string buf uid;
    output_float_le buf freq;
    output_int32_le buf length
  in
  List.iter fn entries;
  Buffer.contents buf

let get_int32_le str off = String.get_int32_le str off |> Int32.to_int

let of_string str =
  let len = get_int32_le str 0 in
  let rec go acc rem =
    if rem < 0 then acc
    else
      let off = 4 + (rem * 32) in
      let uid = String.sub str off 20 in
      let frq = String.get_int64_le str (off + 20) in
      let frq = Int64.float_of_bits frq in
      let len = get_int32_le str (off + 28) in
      go ((uid, frq, len) :: acc) (rem - 1)
  in
  go [] (len - 1)

let uid n =
  let str = Bytes.make 20 '\x00' in
  Bytes.set_uint8 str 0 n;
  Bytes.unsafe_to_string str

let () =
  test "out_postings/in_postings roundtrip in memory" @@ fun () ->
  let entries = [ (uid 1, 3.0, 100); (uid 2, 5.0, 200) ] in
  let str = to_string entries in
  let expected_len = 4 + (2 * 32) in
  assert (String.length str = expected_len);
  let result = of_string str in
  assert (List.length result = 2);
  let check (uid, freq, length) (uid', freq', length') =
    assert (String.equal uid uid');
    assert (freq = freq');
    assert (length = length')
  in
  List.iter2 check entries result

let () =
  test "postings trie serialize/lookup roundtrip via Cachet" @@ fun () ->
  let t = Trie.create () in
  let entries1 = [ (uid 1, 2.0, 50); (uid 2, 7.0, 120) ] in
  let entries2 = [ (uid 3, 1.5, 30) ] in
  Trie.insert t "setrlimit" entries1;
  Trie.insert t "malloc" entries2;
  let tmp = Filename.temp_file "trie" ".bin" in
  let oc = open_out_bin tmp in
  Trie.serialize to_string oc ~pagesize t;
  close_out oc;
  let cache, fd = cachet_of_file tmp in
  let finally () =
    Unix.close fd;
    Sys.remove tmp
  in
  Fun.protect ~finally @@ fun () ->
  let r1 = Trie.lookup cache of_string "setrlimit" in
  let r1 = Option.value ~default:[] r1 in
  assert (List.length r1 = 2);
  let uid1, freq1, len1 = List.hd r1 in
  assert (String.equal uid1 (uid 1));
  assert (freq1 = 2.0);
  assert (len1 = 50);
  let r2 = Trie.lookup cache of_string "malloc" in
  let r2 = Option.value ~default:[] r2 in
  assert (List.length r2 = 1);
  let uid3, freq3, len3 = List.hd r2 in
  assert (String.equal uid3 (uid 3));
  assert (freq3 = 1.5);
  assert (len3 = 30)

let () =
  test "postings trie with many entries per key" @@ fun () ->
  let t = Trie.create () in
  let entries =
    let fn idx = (uid idx, Float.of_int (idx + 1), 100 + idx) in
    List.init 50 fn
  in
  Trie.insert t "common_token" entries;
  let tmp = Filename.temp_file "trie" ".bin" in
  let oc = open_out_bin tmp in
  Trie.serialize to_string oc ~pagesize t;
  close_out oc;
  let cache, fd = cachet_of_file tmp in
  let finally () =
    Unix.close fd;
    Sys.remove tmp
  in
  Fun.protect ~finally @@ fun () ->
  let result = Trie.lookup cache of_string "common_token" in
  let result = Option.value ~default:[] result in
  assert (List.length result = 50);
  let check i (uid', freq, length) =
    assert (String.equal uid' (uid i));
    assert (freq = Float.of_int (i + 1));
    assert (length = 100 + i)
  in
  List.iteri check result

let () =
  test "idf + postings tries side by side" @@ fun () ->
  let idf_t = Trie.create () in
  let idx_t = Trie.create () in
  Trie.insert idf_t "setrlimit" 2.5;
  Trie.insert idf_t "malloc" 1.2;
  Trie.insert idx_t "setrlimit" [ (uid 1, 3.0, 80) ];
  Trie.insert idx_t "malloc" [ (uid 1, 1.0, 80); (uid 2, 4.0, 150) ];
  let tmp_idf = Filename.temp_file "idf" ".bin" in
  let tmp_idx = Filename.temp_file "idx" ".bin" in
  let oc = open_out_bin tmp_idf in
  Trie.serialize float_to_string oc ~pagesize idf_t;
  close_out oc;
  let oc = open_out_bin tmp_idx in
  Trie.serialize to_string oc ~pagesize idx_t;
  close_out oc;
  let idf_cache, idf_fd = cachet_of_file tmp_idf in
  let idx_cache, idx_fd = cachet_of_file tmp_idx in
  let finally () =
    Unix.close idf_fd;
    Unix.close idx_fd;
    Sys.remove tmp_idf;
    Sys.remove tmp_idx
  in
  Fun.protect ~finally @@ fun () ->
  let avgdl = 100.0 in
  let query = [ "setrlimit" ] in
  let scores = Hashtbl.create 16 in
  let fn token =
    match Trie.lookup idf_cache float_of_string token with
    | Some (2.5 as idf) ->
        let entries = Trie.lookup idx_cache of_string token in
        let entries = Option.value ~default:[] entries in
        let fn (uid, freq, length) =
          let _D = Float.of_int length in
          let _n = freq *. (1.5 +. 1.) in
          let _m = freq +. (1.5 *. (1. -. 0.75 +. (0.75 *. _D /. avgdl))) in
          let contribution = idf *. (_n /. _m) in
          let prev =
            match Hashtbl.find_opt scores uid with Some s -> s | None -> 0.0
          in
          Hashtbl.replace scores uid (prev +. contribution)
        in
        List.iter fn entries
    | Some v ->
        Fmt.failwith "Fallback to an unexpected value for %s: %f" token v
    | None -> Fmt.failwith "%s not found" token
  in
  List.iter fn query;
  assert (Hashtbl.length scores = 1);
  let score = Hashtbl.find scores (uid 1) in
  assert (score > 0.0)

let () = Printf.printf "All tests passed.\n"
