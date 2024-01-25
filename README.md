# SecretLinks

### Create a secret (with click-to-reveal enabled)

```bash
curl -X POST -v http://localhost:8080/secret -d '{"secret":"p@ssw0rd","views":4,"click":true}'
```

`secret` is required.  
`views` defaults to 1 if not specified.  
`click` defaults to false if not specified.

Returns the UUID of the created secret.

### Todos

- [ ] Zero-knowledge encryption (decryption key in the URL)
- [ ] Persistent storage (e.g. SQLite?)
- [ ] Maybe access logs
