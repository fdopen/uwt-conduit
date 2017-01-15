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
let try_init_tcp ?sa f =
  let t = Uwt.Tcp.init () in
  Lwt.catch
    ( fun () ->
        (match sa with
        | None -> ()
        | Some addr ->
          Uwt.Tcp.bind_exn t ~addr () );
        f t )
    ( fun exn -> Uwt.Tcp.close_noerr t; Lwt.fail exn )

let accept_close_on_exn server f =
  Lwt.wrap1 Uwt.Tcp.accept_exn server >>= fun t ->
  Lwt.catch ( fun () -> f t ) (fun e -> Uwt.Tcp.close_noerr t ; Lwt.fail e)

let safe_close t =
  Lwt.catch
    (fun () -> Uwt_io.close t)
    (fun _ -> Lwt.return_unit)

let default_on_exn exn = !Lwt.async_exception_hook exn
let process_accept ?(on_exn=default_on_exn)
    ic oc timeout cb cl =
  let close ~ic ~oc () =
    safe_close oc >>= fun () -> safe_close ic
  in
  match cb cl ic oc with
  | exception x ->
    let _ : unit Lwt.t = close ~ic ~oc () in
    on_exn x
  | c ->
    let f () =
      match timeout with
      | None -> c
      | Some t -> Lwt.pick [ c ; Uwt.Timer.sleep (t * 1000) ]
    in
    Lwt.finalize f (close ~ic ~oc) |> Lwt.ignore_result
