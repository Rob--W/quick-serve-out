# quick-serve-out.py

Provides a server with a simple interface to request and receive text
or a file from another endpoint in your network. The result is send to
the standard output.

## HTTPS and certificate

By default, the server form must be accessed over HTTPS, but you can opt out of
this with the `--allow-http` flag.

To generate a self-signed certificate (for `--certfile`), run:

```sh
openssl req -x509 -newkey rsa:4096 -days 360 -keyout localhost.pem -out localhost.pem -nodes -sha256 -subj '/CN=localhost' -addext 'subjectAltName = DNS:localhost, IP:127.0.0.1'
```

The `subjectAltName` part of the certificate is optional, and can be edited if
you want to import the certificates in your browser's trust store.

## Examples

Simple text sharing:

1. `quick-serve-out.py PORT`  (e.g. `quick-serve-out.py 1234`).
2. Visit https://youriphere:PORT/ (e.g. https://127.0.0.1:1234 )
3. Input text and submit.
4. Look at stdout.

File sharing:

1. `quick-serve-out.py PORT > filename`
2. Visit https://youriphere:PORT/
3. Select a file and submit.
4. Look at stderr for the actual name of the uploaded file.
5. Look at stdout (=piped to filename) for the file content.

Via curl instead of a web browser:

1. `quick-serve-out.py PORT`
2. `echo or cat anything | curl https://youriphere:PORT --data-binary @-`
3. Look at stdout.

Via curl with the file name included during transfer:

1. `quick-serve-out.py PORT > filename`
2. curl https://youriphere:PORT -F @path/to/file
3. Look at stderr for the actual name of the uploaded file.
4. Look at stdout (=piped to filename) for the file content.

Use `curl -k` instead of `curl` to ignore the certificate error from your
self-signed certificate.
