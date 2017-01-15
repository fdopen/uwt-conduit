(*
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

open Lwt.Infix

let rand_init = Nocrypto_entropy_uwt.initialize ()

module H = Conduit_uwt_helper

module Client = struct
  let connect ?src host sa =
    rand_init >>= fun () ->
    H.try_init_tcp ?sa:src @@ fun fd ->
    X509_uwt.authenticator `No_authentication_I'M_STUPID >>= fun authenticator ->
    let config = Tls.Config.client ~authenticator () in
    Uwt.Tcp.connect fd ~addr:sa >>= fun () ->
    Tls_uwt.Unix.client_of_fd config ~host fd >|= fun t ->
    let ic, oc = Tls_uwt.of_t t in
    (fd, ic, oc)

end

module Server = struct

  let accept config s =
    H.accept_close_on_exn s @@ fun fd ->
    Tls_uwt.Unix.server_of_fd config fd >|= fun t ->
    let ic, oc = Tls_uwt.of_t t in
    (fd, ic, oc)

  let init ?on_exn ?backlog ~certfile ~keyfile ?stop ?timeout sa callback =
    rand_init >>= fun () ->
    X509_uwt.private_of_pems ~cert:certfile ~priv_key:keyfile >>= fun cert ->
    (match Tls.Config.server ~certificates:(`Single cert) () with
    |exception x -> Lwt.fail x
    | y -> Lwt.return y) >>= fun conf ->
    H.try_init_tcp ~sa Lwt.return >>= fun server ->
    Conduit_uwt_ssl_tls_common.init_server
      ?on_exn ?backlog ?stop ?timeout callback accept conf server
end
