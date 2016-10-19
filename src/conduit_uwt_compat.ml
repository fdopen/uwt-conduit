module Conduit_lwt_unix = Conduit_uwt
module Resolver_lwt_unix = Resolver_uwt
#ifdef HAVE_LWT_TLS
module Conduit_lwt_tls = Conduit_uwt_tls
#endif
#ifdef HAVE_LWT_SSL
module Conduit_lwt_ssl = Conduit_uwt_ssl
#endif
