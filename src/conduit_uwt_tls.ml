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

open Lwt

let rand_init = Nocrypto_entropy_uwt.initialize ()

open Conduit_uwt_helper

module Client = struct
  let connect ?src host sa =
    rand_init >>= fun () ->
    try_init_tcp ( fun fd ->
        (match src with
        | None -> ();
        | Some src_sa -> Uwt.Tcp.bind_exn fd ~addr:src_sa ());
        Lwt.return fd
      ) >>= fun fd ->
    X509_uwt.authenticator `No_authentication_I'M_STUPID >>= fun authenticator ->
    let config = Tls.Config.client ~authenticator () in
    Uwt.Tcp.connect fd ~addr:sa >>= fun () ->
    Tls_uwt.Unix.client_of_fd config ~host fd >|= fun t ->
    let ic, oc = Tls_uwt.of_t t in
    (fd, ic, oc)
end

module Server = struct

  let accept config s =
    Lwt.wrap1 Uwt.Tcp.accept_exn s >>= fun fd ->
    Tls_uwt.Unix.server_of_fd config fd >|= fun t ->
    let ic, oc = Tls_uwt.of_t t in
    (fd, ic, oc)

  let process_accept ~timeout callback (cfd, ic, oc) =
    let c = callback cfd ic oc in
    let events = match timeout with
      | None -> [c]
      | Some t -> [c; (Uwt.Timer.sleep (t * 1_000)) ] in
    Lwt.pick events

  let init ?(nconn=20) ~certfile ~keyfile
      ?(stop = fst (Lwt.wait ())) ?timeout sa callback =
    rand_init >>= fun () ->
    X509_uwt.private_of_pems ~cert:certfile ~priv_key:keyfile >>= fun cert ->
    (match Tls.Config.server ~certificates:(`Single cert) () with
    |exception x -> Lwt.fail x
    | y -> Lwt.return y) >>= fun conf ->
    try_init_tcp ~sa Lwt.return >>= fun server ->
    let sleeper,waker = Lwt.wait () in
    let cb server res =
      if Uwt.Int_result.is_error res then
        let () = Uwt.Tcp.close_noerr server in
        Uwt.Int_result.to_exn ~name:"tcp_listen" res
        |> Lwt.wakeup_exn waker
      else
        let _ : unit Lwt.t =
          Lwt.catch ( fun () ->
              accept conf server >>=
              process_accept ~timeout callback)
            (function
            | Lwt.Canceled ->
              Uwt.Tcp.close_noerr server; (* todo: more graceful *)
              Lwt.wakeup_exn waker Lwt.Canceled;
              Lwt.return_unit
            | _ -> Lwt.return_unit)
        in
        ()
    in
    let er = Uwt.Tcp.listen server ~max:nconn ~cb in
    if Uwt.Int_result.is_error er then
      let () = Uwt.Tcp.close_noerr server in
      Uwt.Int_result.to_exn ~name:"tcp_listen" er
      |> Lwt.fail
    else
      let () =
        async (fun () ->
            stop >>= fun () ->
            Uwt.Tcp.close_noerr server;
            Lwt.wakeup waker ();
            return_unit)
      in
      sleeper
end
