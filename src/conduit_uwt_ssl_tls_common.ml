open Lwt.Infix
let process_accept ~timeout callback (cfd, ic, oc) =
  let close () =
    Conduit_uwt_helper.safe_close oc >>= fun () ->
    Conduit_uwt_helper.safe_close ic
  in
  match callback cfd ic oc with
  | exception x -> close () >>= fun () -> Lwt.fail x
  | c ->
    let events = match timeout with
    | None -> [c]
    | Some t -> [c; (Uwt.Timer.sleep (t * 1_000)) ] in
    let _ : unit Lwt.t = Lwt.pick events >>= close in
    Lwt.return_unit

let init_server ?(nconn=20) ?(stop = fst (Lwt.wait ()))
    ?timeout callback accept x server =
  let sleeper,waker = Lwt.wait () in
  let cb server res =
    if Uwt.Int_result.is_error res then
      let () = Uwt.Tcp.close_noerr server in
      Uwt.Int_result.to_exn ~name:"tcp_listen" res
      |> Lwt.wakeup_exn waker
    else
    let _ : unit Lwt.t =
      Lwt.catch ( fun () ->
          accept x server >>=
          process_accept ~timeout callback)
        (function
        | Lwt.Canceled ->
          Uwt.Tcp.close_noerr server;
          Lwt.wakeup_exn waker Lwt.Canceled;
          Lwt.return_unit
        | x -> !Lwt.async_exception_hook x ; Lwt.return_unit)
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
    Lwt.async (fun () ->
        stop >>= fun () ->
        Uwt.Tcp.close_noerr server;
        Lwt.wakeup waker ();
        Lwt.return_unit)
  in
  sleeper
