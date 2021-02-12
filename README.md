hydepark
========

A discussion forum application for [Gemini](https://gemini.circumlunar.space).

## Preparing for run

### Compilation

You need [Rust](https://www.rust-lang.org) to compile Hydepark. Once you have it, run:

    cargo build --release

### Server SSL certificate

[Gemini](https://gemini.circumlunar.space) protocol mandates the use of TLS encryption, therefore as a prerequisite step you must have a valid SSL certificate.
You can generate your own self-signed server certificate, or obtain one from a CA like [Let's Encrypt](https://letsencrypt.org).

Here's one example for generating self-signed SSL certificate using [OpenSSL](https://www.openssl.org) (replace *example.com* with your own domain name):

    openssl req -newkey rsa:2048 -nodes -keyout example.com.key \
      -nodes -x509 -out example.com.crt -subj "/CN=example.com"

Hydepark works with `.pfx` certificate container. To create one, run:

    openssl pkcs12 -export -out cert.pfx \
      -inkey example.com.key -in example.com.crt

## Running

    RUST_LOG=hydepark=trace ./target/release/hydepark

See [env_logger](https://docs.rs/env_logger) documentation on controlling log verbosity.

## Configuration

The service can be configured using command line arguments. For the list of available options, run: `hydepark -h`.

### Storage

Hydepark uses external storage for storing all the information on users, forum topics, etc. By default, in-memory SQLite is used as a storage. To use persistent storage, configure one of the available storage types:

|Type|Connection string|
|-|-
|SQLite|`sqlite://[<path to SQLite database file>]`|

Example of using persistent SQLite database file:

    RUST_LOG=hydepark=trace ./target/debug/hydepark --db-conn=sqlite://test.db

## Client authentication

Hydepark uses client side SSL certificates for user authentication. Clients can browse existing topics and messages anonymously, but once they wish to create a new topic or write a new message they will be asked to "register" by providing a username. The username will be linked with the SSL certificate currently used.

### Updating client certificate

When client certificate is about to be expired, navigate to `gemini://<hostname>/update-cert-req` and follow the instructions for linking a new certificate with your account.
