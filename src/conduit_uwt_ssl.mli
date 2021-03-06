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

(** TLS/SSL connections via {{:http://www.openssl.org}OpenSSL} C bindings *)

module Client : sig
  val default_ctx : Ssl.context

  val connect :
    ?ctx:Ssl.context ->
    ?src:Unix.sockaddr ->
    Unix.sockaddr ->
    (Uwt.Tcp.t * Uwt_io.input_channel * Uwt_io.output_channel) Lwt.t

end

module Server : sig

  val init :
    ?on_exn:(exn -> unit) ->
    ?ctx:Ssl.context ->
    ?backlog:int ->
    ?password:(bool -> string) ->
    certfile:string ->
    keyfile:string ->
    ?stop:(unit Lwt.t) ->
    ?timeout:int ->
    Unix.sockaddr ->
    (Uwt.Tcp.t -> Uwt_io.input_channel -> Uwt_io.output_channel -> unit Lwt.t) ->
    unit Lwt.t
end
