(* internal only *)
val init_server :
  ?backlog:int ->
  ?stop:unit Lwt.t ->
  ?timeout:int ->
  ('a -> 'b Uwt_io.channel -> 'c Uwt_io.channel -> unit Lwt.t) ->
  ('d -> Uwt.Tcp.t -> ('a * 'b Uwt_io.channel * 'c Uwt_io.channel) Lwt.t) ->
  'd -> Uwt.Tcp.t -> unit Lwt.t
