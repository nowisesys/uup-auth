<!DOCTYPE html>
<!--
Copyright (C) 2014-2015 Anders Lövgren (Nowise Systems/Uppsala University).

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
        <title>PAM Authentication Example</title>
    </head>
    <body>
        <h1>PAM Authentication Example</h1>
        <?php
        // ==========================================================================
        //  PAM module auhentication.
        //  
        //  Demonstrate login using PAM-modules. It's worth noticing that this
        //  authenticator is *not* limited to system local authentication. With a
        //  proper setup of the PAM-stack, this authenticator could be used for
        //  authentication against numerious account sources.
        //  
        //  In addition to install the PAM extension, the authentication sources 
        //  must be readable. For local system account authentication this usually
        //  implies that /etc/shadow should be readable by the user account the
        //  web server is running as:
        //  
        //  bash$> setfacl -m u:apache:r /etc/shadow
        // ==========================================================================

        require_once __DIR__ . '/../vendor/autoload.php';

        use UUP\Authentication\Authenticator\BasicHttpAuthenticator;
        use UUP\Authentication\Validator\PamValidator;

        try {
                $validator = new PamValidator();
                $authenticator = new BasicHttpAuthenticator($validator, "PAM Authentication Example");
                $authenticator->message = "Logon cancelled by caller";
//                        $authenticator->redirect = basename(__FILE__);
                $validator->errlog = true;
                $validator->throws = false;

                if (isset($_GET['login'])) {
                        $authenticator->login();
                }
                if (isset($_GET['logout'])) {
                        $authenticator->logout();
                }

                if ($authenticator->accepted()) {
                        printf("<p>Logged on as %s | <a href=\"?logout\">Logout</a>\n", $authenticator->getSubject());
                } else {
                        printf("<p><a href=\"?login\">Login</a>\n");
                }

                printf("<p>Use a system user account for login.</p>\n");
        } catch (Exception $exception) {
                printf("Exception: %s", $exception);
                $authenticator->logout();
        }

        ?>
    </body>
</html>
