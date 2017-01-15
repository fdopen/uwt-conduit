open Lwt.Infix

let init_server ?(on_exn=Conduit_uwt_helper.default_on_exn)
    ?(backlog=128) ?(stop = fst (Lwt.wait ()))
    ?timeout callback accept x server =
  let sleeper,waker = Lwt.wait () in
  let cb server res =
    if Uwt.Int_result.is_error res then
      let () = Uwt.Tcp.close_noerr server in
      Uwt.Int_result.to_exn ~name:"tcp_listen" res
      |> Lwt.wakeup_exn waker
    else
    let _ : unit Lwt.t =
      Lwt.catch (fun () ->
          accept x server >>= fun (cfd,ic,oc) ->
          Conduit_uwt_helper.process_accept ~on_exn ic oc timeout callback cfd;
          Lwt.return_unit
        )
        (function
        | Lwt.Canceled ->
          Uwt.Tcp.close_noerr server;
          Lwt.wakeup waker ();
          Lwt.return_unit
        | x -> on_exn x ; Lwt.return_unit)
    in
    ()
  in
  let er = Uwt.Tcp.listen server ~max:backlog ~cb in
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
