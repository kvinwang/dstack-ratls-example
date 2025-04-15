# dstack-ratls-example

This example demonstrates how to establish a secure connection using RA-TLS between Dstack apps.

## How to run
1. Clone the dstack-ratls-example repository
```
git clone https://github.com/kvinwang/dstack-ratls-example.git
cd dstack-ratls-example
```
2. Run a dstack simulator
```
socat UNIX-LISTEN:./dstack.sock,fork,mode=777 OPENSSL:9e8af4fc80bde3bea655a161280910c770c8d561-3000.app.kvin.wang:12004
```

3. Run the server in a new terminal
```
cd server/
cat > Rocket.toml <<EOF
[default]
address = "0.0.0.0"
port = 8843

[default.tls]
certs = "./certs/server.crt"
key = "./certs/server.key"

[default.tls.mutual]
ca_certs = "./certs/tmp-ca.crt"
mandatory = false
EOF

DSTACK_AGENT_ADDRESS=unix:../dstack.sock DEMO_DOMAIN=ratls-test.kvin.wang cargo run
```

4. Run the client in a new terminal
```
cd ../client
DSTACK_AGENT_ADDRESS=unix:../dstack.sock cargo run -- https://ratls-test.kvin.wang:8843
```

## Note

- You can substitute the domain ratls-test.kvin.wang with your preferred domain. Remember to configure a DNS record for the domain directing to your test server's IP address.

- Modify the port number 8843 to your desired port number.

- This example requires dstack OS v0.4.2 or later, which is pending release at the time of writing. It will be available in the coming days.
