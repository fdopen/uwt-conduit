(*
 * Copyright (c) 2012-2014 Anil Madhavapeddy <anil@recoil.org>
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

(*  highly modified for uwt, ah *)

open Lwt.Infix
open Conduit_uwt_helper

let _ = Ssl.init ()

let chans_of_fd sock =
  let shutdown () = Uwt_ssl.ssl_shutdown sock in
  let close () =
    Uwt_ssl.close_noerr sock;
    Lwt.return_unit
  in
  let oc =
    Uwt_io.make
      ~mode:Uwt_io.output
      ~close:shutdown
      (fun buf pos len -> Uwt_ssl.write_ba ~pos ~len sock ~buf)
  in
  let ic =
    Uwt_io.make
      ~mode:Uwt_io.input
      ~close
      (fun buf pos len -> Uwt_ssl.read_ba ~len ~pos sock ~buf)
  in
  Uwt_ssl.get_tcp_t sock, ic, oc

module Client = struct
  (* SSL TCP connection *)
  let t = Ssl.create_context Ssl.SSLv23 Ssl.Client_context
  let () = Ssl.disable_protocols t [Ssl.SSLv23]

  let connect ?(ctx=t) ?src addr =
    try_init_tcp ?sa:src @@ fun t ->
    Uwt.Tcp.connect t ~addr >>= fun () ->
    Uwt_ssl.ssl_connect t ctx >|= fun sock ->
    chans_of_fd sock
end

module Server = struct

  let t = Ssl.create_context Ssl.SSLv23 Ssl.Server_context
  let () = Ssl.disable_protocols t [Ssl.SSLv23]

  let accept_real ctx t =
    accept_close_on_exn t @@ fun at ->
    Uwt_ssl.ssl_accept at ctx >|= fun sock ->
    chans_of_fd sock

  let accept ?(ctx=t) t = accept_real ctx t

  let init ?(ctx=t) ?backlog ?password ~certfile ~keyfile
      ?stop ?timeout sa callback =
    (match password with
     | None -> ()
     | Some fn -> Ssl.set_password_callback ctx fn);
    Ssl.use_certificate ctx certfile keyfile;
    try_init_tcp ~sa Lwt.return >>= fun server ->
    Conduit_uwt_ssl_tls_common.init_server
      ?backlog ?stop ?timeout callback accept_real ctx server
end
