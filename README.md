# web-authn-demo

For detailed documentation check doc/paper

## Important notes:

Always use HTTPS
``` sh
http-server . -p 8888 -S -C /Users/julian/certs/server.pem -K /Users/julian/certs/server.key
```

with http-server from npm 

also use local hosts file to add `127.0.0.1   dev.webauthn.demo`