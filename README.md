# http3-ytproxy

A fork of http3-ytproxy adding support for dynamic socket names and port numbers, just because I'am too lazy to change the code enough to use Go routines. So I prefer to run different threads instead.

The socket folder will be created automatically.

## Arguments:

```
  -p string
    	Specify a port number (default "8080")
  -s string
    	Specify a socket name (default "http-proxy.sock")
```

## SystemD service

Copy the `http3-ytproxy@.service` to `/etc/systemd/system/` and use it like this:

```
# This will create the http-proxy-1.sock file
$ sudo systemctl enable --now http3-ytproxy@1.service
# And this one will be http-proxy-2.sock
$ sudo systemctl enable --now http3-ytproxy@2.service
```

lolxdxdxd fastest invidious instance in the fucking world wtfffffffffffffffffffffff
