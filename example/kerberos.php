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
                <title>Remote User (i.e. Kerberos) Authentication Example</title>
        </head>
        <body>
                <h1>Remote User (i.e. Kerberos) Authentication Example</h1>                
                <?php
                // ==========================================================================
                //  Kerberos authentication using RemoteUserAuthenticator class. 
                //  
                //  Notice that the web server has to be configured and the kerberos_auth.conf 
                //  (or equivalent) has to define the login/logout endpoints URLs.
                // ==========================================================================

                require_once __DIR__ . '/../vendor/autoload.php';

                use UUP\Authentication\RemoteUserAuthenticator;

                try {
                        $authenticator = new RemoteUserAuthenticator(
                            array(
                                'login'  => '/login/kerberos',
                                'logout' => '/logout/kerberos'
                            )
                        );

                        if (isset($_GET['login'])) {
                                $authenticator->login();
                        }
                        if (isset($_GET['logout'])) {
                                $authenticator->logout();
                        }

                        if ($authenticator->accepted()) {
                                printf("<p>Logged on as %s | <a href=\"?logout\">Logout</a>\n", $authenticator->getUser());
                        } else {
                                printf("<p><a href=\"?login\">Login</a>\n");
                        }

                        printf("<p>Use a domain user account for login.</p>\n");
                } catch (\Exception $exception) {
                        printf("Exception: %s", $exception);
                }

                ?>
        </body>
</html>
