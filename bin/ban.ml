let ( let@ ) finally fn = Fun.protect ~finally fn
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

let strip_comment line =
  match String.index_opt line '#' with
  | Some idx -> String.sub line 0 idx
  | None -> line

let rem_whitespaces str =
  String.split_on_char ' ' str
  |> List.concat_map (String.split_on_char '\t')
  |> List.filter (fun word -> word <> "")

let is_ipaddr str = Ipaddr.of_string str |> Result.is_ok

let add_line t line =
  let line = strip_comment line in
  let line = String.trim line in
  if String.length line > 0 && line.[0] <> '!' && line.[0] <> ';' then
    begin match rem_whitespaces line with
    | [] -> ()
    | x :: r ->
        let tokens = if is_ipaddr x then r else x :: r in
        let add token =
          match Domain_name.of_string token with
          | Ok v -> Trie.insert t Domain_name.(to_string (canonical v)) ()
          | Error _ -> ()
        in
        List.iter add tokens
    end

let run banlist pagesize output =
  let t = Trie.create () in
  let on_banfile filepath =
    let ic = open_in_bin filepath in
    let@ () = fun () -> close_in ic in
    let rec go () =
      match input_line ic with
      | line -> add_line t line; go ()
      | exception End_of_file -> ()
    in
    go ()
  in
  List.iter on_banfile banlist;
  let oc = open_out_bin output in
  let@ () = fun () -> close_out oc in
  Trie.serialize (Fun.const "") oc ~pagesize t;
  flush oc

open Cmdliner

let pagesize =
  let doc =
    "The pagesize used for our trie file when it is read by the unikernel \
     (formally, the value specified for the $(i,--block-sector-size) option."
  in
  Arg.(value & opt int 512 & info [ "pagesize" ] ~doc ~docv:"PAGESIZE")

let banlist =
  let doc = "A file which contains a list of domains that we should ban." in
  let existing_filepath =
    let parser str =
      match Fpath.of_string str with
      | Ok _ when Sys.file_exists str && Sys.is_regular_file str -> Ok str
      | Ok v -> error_msgf "%a is not an existing regular file" Fpath.pp v
      | Error _ as err -> err
    in
    Arg.conv (parser, Fmt.string)
  in
  let open Arg in
  value
  & opt_all existing_filepath []
  & info [ "b"; "banlist" ] ~doc ~docv:"FILE"

let output =
  let doc = "The image which will be used by the unikernel." in
  let non_existing_filepath =
    let parser str =
      match Fpath.of_string str with
      | Ok _ when Sys.file_exists str = false -> Ok str
      | Ok v -> error_msgf "%a already exists" Fpath.pp v
      | Error _ as err -> err
    in
    Arg.conv (parser, Fmt.string)
  in
  let open Arg in
  required & pos 0 (some non_existing_filepath) None & info [] ~doc ~docv:"FILE"

let term =
  let open Term in
  const run $ banlist $ pagesize $ output

let cmd =
  let info = Cmd.info "annuaire.ban" in
  Cmd.v info term

let () = Cmd.(exit @@ eval cmd)
