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
  let oc = Uwt_ssl.out_channel_of_descr sock in
  let ic = Uwt_ssl.in_channel_of_descr sock in
  Uwt_ssl.get_tcp_t sock, ic, oc

module Client = struct
  (* SSL TCP connection *)
  let t = Ssl.create_context Ssl.SSLv23 Ssl.Client_context
  let () = Ssl.disable_protocols t [Ssl.SSLv23]

  let connect ?(ctx=t) ?src addr =
    try_init_tcp ( fun fd ->
        (match src with
        | None -> ();
        | Some src_sa -> Uwt.Tcp.bind_exn fd ~addr:src_sa ());
        Lwt.return fd
      ) >>= fun t ->
    Uwt.Tcp.connect t ~addr >>= fun () ->
    Uwt_ssl.ssl_connect t ctx >>= fun sock ->
    Lwt.return (chans_of_fd sock)
end

module Server = struct

  let t = Ssl.create_context Ssl.SSLv23 Ssl.Server_context
  let () = Ssl.disable_protocols t [Ssl.SSLv23]

  let accept_real ctx t =
    Lwt.wrap1 Uwt.Tcp.accept_exn t >>= fun at ->
    Lwt.try_bind (fun () -> Uwt_ssl.ssl_accept at ctx)
      (fun sock -> Lwt.return (chans_of_fd sock))
      (fun exn -> Uwt.Tcp.close_noerr at; Lwt.fail exn)

  let accept ?(ctx=t) t = accept_real ctx t

  let init ?(ctx=t) ?nconn ?password ~certfile ~keyfile
      ?stop ?timeout sa callback =
    (match password with
     | None -> ()
     | Some fn -> Ssl.set_password_callback ctx fn);
    Ssl.use_certificate ctx certfile keyfile;
    try_init_tcp ~sa Lwt.return >>= fun server ->
    Conduit_uwt_ssl_tls_common.init_server
      ?nconn ?stop ?timeout callback accept_real ctx server
end
