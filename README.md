# SecretLinks

### Create a secret (with click-to-reveal enabled)

```bash
curl -X POST -v http://localhost:8080/secret -d '{"secret":"p@ssw0rd","views":4,"click":true}'
```

`secret` is required.  
`views` defaults to 1 if not specified.  
`click` defaults to false if not specified.  
`expires` days before the secret is deleted. defaults to 3 if not specified or less than 1.

Returns the URL path to view the created secret.
