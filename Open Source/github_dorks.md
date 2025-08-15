# GitHub Dorks

## Basic README.md Searches
```
filename:README.md
path:/README.md
extension:md
```

## README.md with Specific Content
```
filename:README.md "password"
filename:README.md "credentials"
filename:README.md "secret"
filename:README.md "api key"
filename:README.md "private key"
filename:README.md "database"
```

## README.md in Specific Contexts
```
filename:README.md language:python
filename:README.md language:javascript
filename:README.md repo:owner/repo
filename:README.md user:username
```

## README.md with Security Concerns
```
filename:README.md "DO NOT MAKE PUBLIC"
filename:README.md "confidential"
filename:README.md "internal use only"
filename:README.md "sample.env"
```

## Advanced Combinations
```
filename:README.md "config" AND "password"
filename:README.md size:>10000
filename:README.md created:>2023-01-01
```
