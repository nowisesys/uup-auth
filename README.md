## UUP-AUTH - Authentication stack for PHP

The uup-auth package provides a library for stacking authenticators together
to support multiple authentication method in a uniform way. 

Bundled are also restrictors for performing access restriction (i.e. on 
time of day or the ip-address/hostname). All authenticators in the stack can
be set as required or sufficient to enforce logon policy (i.e. require CAS-logon
from outside of LAN while supporting Kerberos logon from inside).

The library is modular. The authenticators are the frontend (credentials
obtainers) that might use a validator as authentication source (for example
LDAP). The authenticator can be combined with a storage object to support
logon sessions. 

Authenticators can be used in a stack or standalone (single login method). If
configuring a stack, use one of the access classes for easy access to chains
and authenticators.

    +-- UUP/Authentication/
          +-- Authenticator/        : Authenticator frontend classes.
          +-- Restrictor/           : Restrictor classes.
          +-- Stack/                : Support for stacking authenticators/restrictors.
          +-- Storage/              : Persistance support.
          +-- Validator/            : Authentication support.

Visit the [project page](https://nowise.se/oss/uup-auth) for more information.
