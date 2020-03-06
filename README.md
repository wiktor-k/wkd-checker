# Web Key Directory checker

This projects aims to provide a lint service for Web Key Directory deployments.

Currently it exposes a REST endpoint that can be queried:

```
curl --data-binary '{"email":"test-wkd@metacode.biz"}' localhost:3000
```

For online version see: https://metacode.biz/openpgp/web-key-directory
