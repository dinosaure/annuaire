type 'a t

val create : unit -> _ t
val find : 'a t -> string -> 'a
val iter : (string -> 'a -> unit) -> 'a t -> unit
val insert : 'a t -> string -> 'a -> unit
val serialize : ('a -> string) -> out_channel -> pagesize:int -> 'a t -> unit
val lookup : 'fd Cachet.t -> (string -> 'a) -> string -> 'a option
val exists : 'fd Cachet.t -> string -> bool
