# helloTLS13

```sh
~$ curl -v -k https://localhost:8443/asd 
*   Trying 127.0.0.1:8443...
* Connected to localhost (127.0.0.1) port 8443 (#0)
[...]
* SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256
* ALPN, server did not agree to a protocol
* Server certificate:
*  subject: CN=example
*  issuer: CN=example
*  SSL certificate verify result: self-signed certificate (18), continuing anyway.
> GET /asd HTTP/1.1
> Host: localhost:8443
> User-Agent: curl/7.81.0
> Accept: */*
> 
< HTTP/1.1 200
< Content-Length: 12
< 
Hello World
```

## Project Background

I needed a simple and modifiable TLS implementation to experiment with kTLS offload.

## Goals

* Understand: Serve as a learning tool to gain a better understanding of the TLS 1.3 protocol.
* Simplify: Minimize abstractions where possible (e.g., hmac vs hkdf, and limited number of crypto primitives).
* Experiment: Prepare as many strings as possible in advance, including all TLS Handshake records.

## Non-Goals

* Compliance: Focus on a single cipher suite and single key. Sufficient for compatibility with curl and Chromium.
* Maintainability: no tests, static keys...

## References

* https://jvns.ca/blog/2022/03/23/a-toy-version-of-tls/
* https://tls13.xargs.org/
* https://github.com/jvns/tiny-tls/
* https://github.com/Liam-lyr/pyTLS_13
