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
                <title>Session Authenticator Example</title>
        </head>
        <body>
                <h1>Session Authenticator Example</h1>
                <?php
                // ==========================================================================
                //  Session authenticator
                //  
                //  Demonstrate wrapping an authenticator in a session authenticator. Its
                //  worth noticing that the session authenticator acts as a delegate for the
                //  wrapped authenticator. The session authenticator is not limited to using
                //  PHP sessions, it can be any supported storage class.
                //  
                //  This example uses the shadow password file for authentication. This 
                //  usually requires that /etc/shadow is readable by the user account the
                //  web server is running as:
                //  
                //  bash$> setfacl -m u:apache:r /etc/shadow
                // ==========================================================================

                require_once __DIR__ . '/../../vendor/autoload.php';

                use UUP\Authentication\Validator\ShadowValidator,
                    UUP\Authentication\Storage\SessionStorage,
                    UUP\Authentication\BasicHttpAuthenticator,
                    UUP\Authentication\SessionAuthenticator;

                try {
                        $auth = new BasicHttpAuthenticator(new ShadowValidator(), "Session Authenticator Example");
                        $stor = new SessionStorage('shadow', false);
                        $session = new SessionAuthenticator($auth, $stor);

                        if (isset($_GET['login'])) {
                                $session->login();
                        }
                        if (isset($_GET['logout'])) {
                                $session->logout();
                        }

                        if ($session->authenticated()) {
                                printf("<p>Logged on as %s | <a href=\"?logout\">Logout</a>\n", $session->getUser());
                        } else {
                                printf("<p><a href=\"?login\">Login</a>\n");
                        }

                        printf("<p>Use a system user account for login.</p>\n");
                } catch (\Exception $exception) {
                        printf("Exception: %s", $exception);
                        $session->logout();
                }

                ?>
        </body>
</html>
