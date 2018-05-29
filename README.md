# EGI BDII Hard Profile

This is the Inspec profile for the BDII hardening.
The BDII is essentially an LDAP server.

## Test coverage

We aim to provide coverage for:

- best practice in deploying ldap
- known vulnerabilities in openldap server and client

These are implemented in controls `openldap-best-practice`, `openldap-cve` and `bdii` - see [controls](controls)
