<!DOCTYPE html>
<!--
Copyright (C) 2014 Anders Lövgren (QNET/BMC CompDept).

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->
<html>
        <head>
                <meta charset="UTF-8">
                <title>Authentication Stack Example</title>
        </head>
        <body>
                <h1>Authentication Stack Example</h1>
                <?php
                // ==========================================================================
                //  Authentication Stack Example
                //  
                //  This example demonstrate how to use a stack of authenticators. The 
                //  caller can select the authentication method from the list of visible 
                //  authenticators. Hidden authenticators can be used for enforcing access
                //  restrictions.
                //  
                //  This example uses the object interface for setting up the chain of
                //  authenticators.
                // ==========================================================================

                require_once __DIR__ . '/../../vendor/autoload.php';

                use UUP\Authentication\Stack\AuthenticatorStack,
                    UUP\Authentication\Authenticator,
                    UUP\Authentication\AddressRestrictor,
                    UUP\Authentication\BasicHttpAuthenticator,
                    UUP\Authentication\CasAuthenticator,
                    UUP\Authentication\Validator\PamValidator,
                    UUP\Authentication\Validator\LdapBindValidator;

                class LdapAuthenticator extends BasicHttpAuthenticator
                {

                        public function __construct($host, $port = 636)
                        {
                                parent::__construct(
                                    new LdapBindValidator($host, $port), 'LDAP Authentication'
                                );
                        }

                }

                class SystemAuthentication extends BasicHttpAuthenticator
                {

                        public function __construct()
                        {
                                parent::__construct(
                                    new PamValidator(), 'System Authentication'
                                );
                        }

                }

                class Authentication extends AuthenticatorStack
                {

                        public function __construct()
                        {
                                $chain = array();

                                // 
                                // Plugin account authenticator objects in stack:
                                // 
                                $chain['auth']['pam'] = (new SystemAuthentication())
                                    ->visible(true)
                                    ->control(Authenticator::sufficient)
                                    ->name('System')
                                    ->description('Login using local system account.');
                                $chain['auth']['cas'] = (new CasAuthenticator('cas.example.com'))
                                    ->visible(true)
                                    ->control(Authenticator::sufficient)
                                    ->name('CAS')
                                    ->description('CAS server login');
                                $chain['auth']['ldap'] = (new LdapAuthenticator('ldaps://ldap.example.com'))
                                    ->visible(true)
                                    ->control(Authenticator::sufficient)
                                    ->name('LDAP')
                                    ->description('LDAP authentication');
                                // 
                                // Add some login restrictions:
                                // 
                                $chain['access']['addr'] = (new AddressRestrictor(array('::1', '127.0.0.1', '192.168.0.0/16')))
                                    ->visible(false)
                                    ->control(Authenticator::required);

                                parent::__construct($chain);
                        }

                        public function getName()
                        {
                                return $this->getAuthenticator()->name;
                        }

                }

                try {
                        $authenticator = new Authentication();

                        if (isset($_GET['login'])) {
                                $authenticator->activate($_GET['login']);
                                $authenticator->login();
                        }
                        if (isset($_GET['logout'])) {
                                $authenticator->logout();
                        }

                        if ($authenticator->authenticated()) {
                                printf("<p>Logged on to %s as %s | <a href=\"?logout\">Logout</a>\n", $authenticator->getName(), $authenticator->getUser());
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
                } catch (\Exception $exception) {
                        printf("Exception: %s", $exception);
                }

                ?>
        </body>
</html>
