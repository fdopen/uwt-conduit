(*
 * Copyright (c) 2012-2014 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2014 Hannes Mehnert <hannes@mehnert.org>
 * Copyright (c) 2015 Andreas Hauptmann
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)

open Lwt
open Sexplib.Conv
open Conduit_uwt_helper

let debug = ref false
let debug_print = ref Printf.eprintf
let () =
  try
    ignore(Sys.getenv "CONDUIT_DEBUG");
    debug := true
  with Not_found -> ()

type tls_lib = | OpenSSL | Native | No_tls [@@deriving sexp]
let tls_library = ref No_tls
let () =
#ifdef HAVE_LWT_SSL
#ifdef HAVE_LWT_TLS
    tls_library := try
        match Sys.getenv "CONDUIT_TLS" with
        | "native" | "Native" | "NATIVE" -> Native
        | _ -> OpenSSL
      with Not_found -> OpenSSL
#else
    tls_library := OpenSSL
#endif
#else
#ifdef HAVE_LWT_TLS
      tls_library := Native
#else
      tls_library := No_tls
#endif
#endif

let () = if !debug then
  !debug_print "Selected TLS library: %s\n"
    (Sexplib.Sexp.to_string (sexp_of_tls_lib !tls_library))

type +'a io = 'a Lwt.t
type ic = Uwt_io.input_channel
type oc = Uwt_io.output_channel

type client_tls_config =
  [ `Hostname of string ] *
  [ `IP of Ipaddr.t ] *
  [ `Port of int ]
[@@deriving sexp]

type client = [
  | `TLS of client_tls_config
  | `TLS_native of client_tls_config
  | `OpenSSL of client_tls_config
  | `TCP of [ `IP of Ipaddr.t ] * [`Port of int ]
  | `Unix_domain_socket of [ `File of string ]
  | `Vchan_direct of [ `Domid of int ] * [ `Port of string ]
  | `Vchan_domain_socket of [ `Domain_name of string ] * [ `Port of string ]
] [@@deriving sexp]

(** Configuration fragment for a listening TLS server *)
type server_tls_config =
  [ `Crt_file_path of string ] *
  [ `Key_file_path of string ] *
  [ `Password of bool -> string | `No_password ] *
  [ `Port of int ]
[@@deriving sexp]

(** Set of supported listening mechanisms that are supported by this module. *)
type server = [
  | `TLS of server_tls_config
  | `OpenSSL of server_tls_config
  | `TLS_native of server_tls_config
  | `TCP of [ `Port of int ]
  | `Unix_domain_socket of [ `File of string ]
  | `Vchan_direct of int * string
  | `Vchan_domain_socket of string  * string
] [@@deriving sexp]

type tls_server_key = [
  | `None
  | `TLS of
      [ `Crt_file_path of string ] *
      [ `Key_file_path of string ] *
      [ `Password of bool -> string | `No_password ]
] [@@deriving sexp]

type ctx = {
  src: Unix.sockaddr option;
  tls_server_key: tls_server_key;
}

let string_of_unix_sockaddr sa =
  let open Unix in
  match sa with
  | ADDR_UNIX s ->
      Printf.sprintf "ADDR_UNIX(%s)" s
  | ADDR_INET (ia, port) ->
      Printf.sprintf "ADDR_INET(%s,%d)" (string_of_inet_addr ia) port

let sexp_of_ctx ctx =
  [%sexp_of: string option * tls_server_key ]
    ((match ctx.src with
      | None -> None
      | Some sa -> Some (string_of_unix_sockaddr sa)),
     ctx.tls_server_key)

type tcp_flow = {
  fd: Uwt.Tcp.t sexp_opaque;
  ip: Ipaddr.t;
  port: int;
} [@@deriving sexp]

type domain_flow = {
  fd: Uwt.Pipe.t sexp_opaque;
  path: string;
} [@@deriving sexp]

type vchan_flow = {
  domid: int;
  port: string;
} [@@deriving sexp]

type flow =
  | TCP of tcp_flow
  | Domain_socket of domain_flow
  | Vchan of vchan_flow
[@@deriving sexp]

let default_ctx =
  { src=None; tls_server_key=`None }

let init ?src ?(tls_server_key=`None) () =
  match src with
  | None ->
    return { src=None; tls_server_key }
  | Some host ->
    Lwt. catch
      ( fun () ->
          Uwt.Dns.getaddrinfo ~host
            ~service:"0"
            [Unix.AI_PASSIVE;Unix.AI_SOCKTYPE Unix.SOCK_STREAM] )
      ( fun x ->
          match x with
          | Uwt.Uwt_error _ -> Lwt.return_nil
          | x -> Lwt.fail x ) >>= function
    | {Uwt.Dns.ai_addr;_}::_ -> Lwt.return { src= Some ai_addr; tls_server_key }
    | [] -> fail (Failure "Invalid conduit source address specified")

let safe_close t =
  Lwt.catch
    (fun () -> Uwt_io.close t)
    (fun _ -> return_unit)

let try_init_pipe f =
  let t = Uwt.Pipe.init () in
  Lwt.catch
    ( fun () -> f t )
    ( fun exn -> Uwt.Pipe.close_noerr t; Lwt.fail exn )

(* Vanilla sockaddr connection *)
module Sockaddr_client = struct
  let connect_tcp ?src sa =
    try_init_tcp ( fun st ->
        (match src with
        | None -> ();
        | Some addr -> Uwt.Tcp.bind_exn st ~addr ());
        Uwt.Tcp.connect st ~addr:sa >|= fun () ->
        let ic = Uwt_io.of_tcp ~mode:Uwt_io.input st in
        let oc = Uwt_io.of_tcp ~mode:Uwt_io.output st in
        st, ic, oc)

  let connect_pipe ?src path =
    try_init_pipe ( fun st ->
        (match src with
        | None -> ()
        | Some src_sa ->
          Uwt.Pipe.bind_exn st ~path:src_sa);
        Uwt.Pipe.connect st ~path >|= fun () ->
        let ic = Uwt_io.of_pipe ~mode:Uwt_io.input st in
        let oc = Uwt_io.of_pipe ~mode:Uwt_io.output st in
        st, ic, oc )
end

module Sockaddr_server = struct
  let process_accept c ic oc timeout =
    let f () =
      match timeout with
      | None -> c
      | Some t -> Lwt.pick [ c ; Uwt.Timer.sleep (t * 1000) ]
    in
    let _ : unit Lwt.t = (* result ignored upstream *)
      Lwt.finalize f
        ( fun () -> safe_close oc >>= fun () -> safe_close ic )
    in
    ()
end

module Sockaddr_server_tcp = struct
  let init ~sockaddr ?(stop = fst (Lwt.wait ())) ?timeout callback =
    try_init_tcp ~sa:sockaddr Lwt.return >>= fun server ->
    let sleeper,waker = Lwt.wait () in
    let abort exn =
      Uwt.Tcp.close_noerr server;
      Lwt.wakeup_exn waker exn
    in
    let cb server res =
      if Uwt.Int_result.is_error res then
        Uwt.Int_result.to_exn ~name:"tcp_listen" res |> abort
      else
        match Uwt.Tcp.accept server with
        | Error x -> abort (Uwt.Uwt_error(x,"tcp_accept",""))
        | Ok client ->
          (* TODO: should I really abort if nodelay fails like the Lwt_unix
             solution? *)
          let _ : unit Uwt.Int_result.t = Uwt.Tcp.nodelay client true in
          let ic = Uwt_io.of_tcp ~mode:Uwt_io.input client
          and oc = Uwt_io.of_tcp ~mode:Uwt_io.output client in
          match callback client ic oc with
          | exception x -> Uwt.Tcp.close_noerr client ; abort x
          | c -> Sockaddr_server.process_accept c ic oc timeout
    in
    (* dubious magic value 15 is from upstream source, why not more? *)
    let er = Uwt.Tcp.listen server ~max:15 ~cb in
    if Uwt.Int_result.is_error er then
      let () = Uwt.Tcp.close_noerr server in
      Uwt.Int_result.to_exn ~name:"tcp_listen" er
      |> Lwt.fail
    else
      let () = async @@ fun () ->
        stop >|= fun () ->
        Uwt.Tcp.close_noerr server;
        Lwt.wakeup waker ()
      in
      sleeper
end

module Sockaddr_server_pipe = struct
  (* TODO: this code duplication is really ugly.
     But my first attempt to functorize led to even uglier code,
     because Uwt.Pipe and Uwt.Tcp have slightly different apis.. *)
  let init ~path ?(stop = fst (Lwt.wait ())) ?timeout callback =
    try_init_pipe (fun s -> Uwt.Pipe.bind_exn s ~path; Lwt.return s)
    >>= fun server ->
    let sleeper,waker = Lwt.wait () in
    let abort exn =
      Uwt.Pipe.close_noerr server;
      Lwt.wakeup_exn waker exn
    in
    let cb server res =
      if Uwt.Int_result.is_error res then
        Uwt.Int_result.to_exn ~name:"pipe_listen" res |> abort
      else
        let client = Uwt.Pipe.init () in
        let r =  Uwt.Pipe.accept_raw ~server ~client in
        if Uwt.Int_result.is_error r then
          let () = Uwt.Pipe.close_noerr client in
          Uwt.Int_result.to_exn ~name:"pipe_accpet" r |> abort
        else
          let ic = Uwt_io.of_pipe ~mode:Uwt_io.input client
          and oc = Uwt_io.of_pipe ~mode:Uwt_io.output client in
          match callback client ic oc with
          | exception x -> Uwt.Pipe.close_noerr client ; abort x
          | c -> Sockaddr_server.process_accept c ic oc timeout
    in
    let er = Uwt.Pipe.listen server ~max:15 ~cb in
    if Uwt.Int_result.is_error er then
      let () = Uwt.Pipe.close_noerr server in
      Uwt.Int_result.to_exn ~name:"pipe_listen" er |> Lwt.fail
    else
      let () = async @@ fun () ->
        stop >|= fun () ->
        Uwt.Pipe.close_noerr server;
        Lwt.wakeup waker ()
      in
      sleeper
end


(** TLS client connection functions *)

#ifdef HAVE_LWT_TLS
let connect_with_tls_native ~ctx (`Hostname hostname, `IP ip, `Port port) =
  let sa = Unix.ADDR_INET (Ipaddr_unix.to_inet_addr ip,port) in
  Conduit_uwt_tls.Client.connect ?src:ctx.src hostname sa >|= fun (fd, ic, oc) ->
  TCP { fd ; ip ; port }, ic, oc
#else
let connect_with_tls_native ~ctx:_ _ =
   fail (Failure "No TLS support compiled into Conduit")
#endif

#ifdef HAVE_LWT_SSL
let connect_with_openssl ~ctx (`Hostname hostname, `IP ip, `Port port) =
  let sa = Unix.ADDR_INET (Ipaddr_unix.to_inet_addr ip,port) in
  Conduit_uwt_ssl.Client.connect ?src:ctx.src sa >|= fun (fd, ic, oc) ->
  TCP { fd ; ip ; port }, ic, oc
#else
let connect_with_openssl ~ctx:_ _ =
  fail (Failure "No SSL support compiled into Conduit")
#endif

let connect_with_default_tls ~ctx tls_client_config =
  match !tls_library with
  | OpenSSL -> connect_with_openssl ~ctx tls_client_config
  | Native -> connect_with_tls_native ~ctx tls_client_config
  | No_tls -> fail (Failure "No SSL or TLS support compiled into Conduit")

(** VChan connection functions *)
#ifdef HAVE_VCHAN_LWT
let connect_with_vchan_lwt ~ctx (`Domid domid, `Port sport) =
  (match Vchan.Port.of_string sport with
   | `Error s -> fail (Failure ("Invalid vchan port: " ^ s))
   | `Ok p -> return p)
  >>= fun port ->
  let flow = Vchan { domid; port=sport } in
  Vchan_lwt_unix.open_client ~domid ~port () >>= fun (ic, oc) ->
  return (flow, ic, oc)
#else
let connect_with_vchan_lwt ~ctx:_ _ =
  fail (Failure "No Vchan support compiled into Conduit")
#endif

(** Main connection function *)

let connect ~ctx (mode:client) =
  match mode with
  | `TCP (`IP ip, `Port port) ->
    let sa = Unix.ADDR_INET (Ipaddr_unix.to_inet_addr ip, port) in
    Sockaddr_client.connect_tcp ?src:ctx.src sa
    >|= fun (fd, ic, oc) ->
    TCP {fd;ip;port}, ic, oc
  | `Unix_domain_socket (`File path) ->
    Sockaddr_client.connect_pipe path >|= fun (fd, ic, oc) ->
    Domain_socket {fd; path}, ic, oc
  | `TLS c -> connect_with_default_tls ~ctx c
  | `OpenSSL c -> connect_with_openssl ~ctx c
  | `TLS_native c -> connect_with_tls_native ~ctx c
  | `Vchan_direct c -> connect_with_vchan_lwt ~ctx c
  | `Vchan_domain_socket _uuid ->
     fail (Failure "Vchan_domain_socket not implemented")

let sockaddr_on_tcp_port ctx port =
  let open Unix in
  match ctx.src with
  | Some (ADDR_UNIX _) -> raise (Failure "Cant listen to TCP on a domain socket")
  | Some (ADDR_INET (a,_)) -> ADDR_INET (a,port), Ipaddr_unix.of_inet_addr a
  | None -> ADDR_INET (inet_addr_any,port), Ipaddr.(V4 V4.any)

#ifdef HAVE_LWT_SSL
let serve_with_openssl ?timeout ?stop ~ctx ~certfile ~keyfile
                       ~pass ~port callback t =
  let sockaddr, ip = sockaddr_on_tcp_port ctx port in
  let password =
    match pass with
    | `No_password -> None
    | `Password fn -> Some fn
  in
  Conduit_uwt_ssl.Server.init
    ?password ~certfile ~keyfile ?timeout ?stop sockaddr
    (fun fd ic oc -> callback (TCP {fd;ip;port}) ic oc) >>= fun () ->
  t
#else
let serve_with_openssl ?timeout:_ ?stop:_ ~ctx:_ ~certfile:_ ~keyfile:_
                       ~pass:_ ~port:_ _ _ =
  fail (Failure "No SSL support compiled into Conduit")
#endif

#ifdef HAVE_LWT_TLS
let serve_with_tls_native ?timeout ?stop ~ctx ~certfile ~keyfile
                          ~pass ~port callback t =
  let sockaddr, ip = sockaddr_on_tcp_port ctx port in
  (match pass with
    | `No_password -> return ()
    | `Password _ -> fail (Failure "OCaml-TLS cannot handle encrypted pem files")
  ) >>= fun () ->
  Conduit_uwt_tls.Server.init
    ~certfile ~keyfile ?timeout ?stop sockaddr
    (fun fd ic oc -> callback (TCP {fd;ip;port}) ic oc)
  >>= fun () -> t
#else
let serve_with_tls_native ?timeout:_ ?stop:_ ~ctx:_ ~certfile:_ ~keyfile:_
                          ~pass:_ ~port:_ _ _ =
  fail (Failure "No TLS support compiled into Conduit")
#endif

let serve_with_default_tls ?timeout ?stop ~ctx ~certfile ~keyfile
                           ~pass ~port callback t =
  match !tls_library with
  | OpenSSL -> serve_with_openssl ?timeout ?stop ~ctx ~certfile ~keyfile
                                 ~pass ~port callback t
  | Native -> serve_with_tls_native ?timeout ?stop ~ctx ~certfile ~keyfile
                                   ~pass ~port callback t
  | No_tls -> fail (Failure "No SSL or TLS support compiled into Conduit")

let serve ?timeout ?stop ~(ctx:ctx) ~(mode:server) callback =
  let t, _u = Lwt.task () in (* End this via Lwt.cancel *)
  Lwt.on_cancel t (fun () -> print_endline "Terminating server thread");
  match mode with
  | `TCP (`Port port) ->
       let sockaddr, ip = sockaddr_on_tcp_port ctx port in
       Sockaddr_server_tcp.init ~sockaddr ?timeout ?stop
         (fun fd ic oc -> callback (TCP {fd; ip; port}) ic oc)
       >>= fun () -> t
  | `Unix_domain_socket (`File path) ->
     Sockaddr_server_pipe.init ~path ?timeout ?stop
       (fun fd ic oc -> callback (Domain_socket {fd;path}) ic oc)
     >>= fun () -> t
  | `TLS (`Crt_file_path certfile, `Key_file_path keyfile, pass, `Port port) ->
     serve_with_default_tls ?timeout ?stop ~ctx ~certfile ~keyfile
                            ~pass ~port callback t
  | `OpenSSL (`Crt_file_path certfile, `Key_file_path keyfile,
              pass, `Port port) ->
     serve_with_openssl ?timeout ?stop ~ctx ~certfile ~keyfile
                        ~pass ~port callback t
  | `TLS_native (`Crt_file_path certfile, `Key_file_path keyfile,
                 pass, `Port port) ->
     serve_with_tls_native ?timeout ?stop ~ctx ~certfile ~keyfile
                           ~pass ~port callback t
  |`Vchan_direct (domid, sport) ->
#ifdef HAVE_VCHAN_LWT
    begin match Vchan.Port.of_string sport with
      | `Error s -> fail (Failure ("Invalid vchan port: " ^ s))
      | `Ok p -> return p
    end >>= fun port ->
    Vchan_lwt_unix.open_server ~domid ~port () >>= fun (ic, oc) ->
    callback (Vchan {domid; port=sport}) ic oc
#else
    let _ = domid and _ = sport in
    fail (Failure "No Vchan support compiled into Conduit")
#endif
  | `Vchan_domain_socket _ ->
    fail (Failure "Vchan_domain_socket not implemented")

let endp_of_flow = function
  | TCP { ip; port; _ } -> `TCP (ip, port)
  | Domain_socket { path; _ } -> `Unix_domain_socket path
  | Vchan { domid; port } -> `Vchan_direct (domid, port)

(** Use the configuration of the server to interpret how to
    handle a particular endpoint from the resolver into a
    concrete implementation of type [client] *)
let endp_to_client ~ctx:_ (endp:Conduit.endp) : client Lwt.t =
  match endp with
  | `TCP (ip, port) -> return (`TCP (`IP ip, `Port port))
  | `Unix_domain_socket file -> return (`Unix_domain_socket (`File file))
  | `Vchan_direct (domid, port) ->
     return (`Vchan_direct (`Domid domid, `Port port))
  | `Vchan_domain_socket (name, port) ->
     return (`Vchan_domain_socket (`Domain_name name, `Port port))
  | `TLS (host, (`TCP (ip, port))) ->
     return (`TLS (`Hostname host, `IP ip, `Port port))
  | `TLS (host, endp) -> begin
       fail (Failure (Printf.sprintf
         "TLS to non-TCP currently unsupported: host=%s endp=%s"
         host (Sexplib.Sexp.to_string_hum (Conduit.sexp_of_endp endp))))
  end
  | `Unknown err -> fail (Failure ("resolution failed: " ^ err))

let endp_to_server ~ctx (endp:Conduit.endp) =
  match endp with
  | `Unix_domain_socket path -> return (`Unix_domain_socket (`File path))
  | `TLS (_host, `TCP (_ip, port)) -> begin
       match ctx.tls_server_key with
       | `None -> fail (Failure "No TLS server key configured")
       | `TLS (`Crt_file_path crt, `Key_file_path key, pass) ->
          return (`TLS (`Crt_file_path crt, `Key_file_path key,
            pass, `Port port))
     end
  | `TCP (_ip, port) -> return (`TCP (`Port port))
  | `Vchan_direct _ as mode -> return mode
  | `Vchan_domain_socket _ as mode -> return mode
  | `TLS (_host, _) -> fail (Failure "TLS to non-TCP currently unsupported")
  | `Unknown err -> fail (Failure ("resolution failed: " ^ err))
