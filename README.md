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

### Example

A typical authentication/authorization stack providing login thru PAM, CAS and 
LDAP with restriction on network and logon time might look like this:

```php
class Authentication extends AuthenticatorStack
{

    public function __construct()
    {
        $chain = array(
            // 
            // Plugin account authenticator objects in stack:
            // 
            'auth'   => array(
                'pam'  => (new SystemAuthentication())
                    ->visible(true)
                    ->control(Authenticator::SUFFICIENT)
                    ->name('System')
                    ->description('Login using local system account.'),
                'cas'  => (new CasAuthenticator('cas.example.com'))
                    ->visible(true)
                    ->control(Authenticator::SUFFICIENT)
                    ->name('CAS')
                    ->description('CAS server login'),
                'ldap' => (new LdapAuthenticator('ldaps://ldap.example.com'))
                    ->visible(true)
                    ->control(Authenticator::SUFFICIENT)
                    ->name('LDAP')
                    ->description('LDAP authentication')
            ),
            // 
            // Add some login restrictions:
            // 
            'access' => array(
                'addr' => (new AddressRestrictor(array('::1', '127.0.0.1', '192.168.0.0/16')))
                    ->visible(false)
                    ->control(Authenticator::REQUIRED),
                'time' => (new DateTimeRestrictor('08:45', '16:30'))
                    ->visible(false)
                    ->control(Authenticator::REQUIRED)
            )
        );

        parent::__construct($chain);
    }

    public function getName()
    {
        return $this->getAuthenticator()->name;
    }

}
```

Somewhere (typical dispatcher or main template) add some code to handle
login/logout request and render logon form:

```php

try {
    $authenticator = new Authentication();

    if (filter_has_var(INPUT_GET, 'login')) {
        $authenticator->activate(filter_input(INPUT_GET, 'login'));
        $authenticator->login();
    }
    if (filter_has_var(INPUT_GET, 'logout')) {
        $authenticator->logout();
    }

    if ($authenticator->accepted()) {
        printf("<p>Logged on to %s as %s | <a href=\"?logout\">Logout</a>\n", $authenticator->getName(), $authenticator->getSubject());
    } else {
        printf("<form action=\"\" method=\"GET\">\n");
        printf("<select name=\"login\">\n");
        foreach ($authenticator->authenticators(true) as $key => $obj) {
            printf("<option value=\"%s\" title=\"%s\">%s</option>\n", $key, $obj->description, $obj->name);
        }
        printf("</select>\n");
        printf("<input type=\"submit\" value=\"Login\">\n");
        printf("</form>\n");
    }
} catch (Exception $exception) {
    die(sprintf("Exception: %s", $exception));
}
```

Visit the [project page](https://nowise.se/oss/uup-auth) for more information.
