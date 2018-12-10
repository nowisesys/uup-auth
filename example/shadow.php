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
        <title>Shadow Password Authentication Example</title>
    </head>
    <body>
        <h1>Shadow Password Authentication Example</h1>
        <?php
        // ==========================================================================
        //  Shadow password file authentication.
        //  
        // See notes in ShadowValidator.php before trying this example together 
        // with the shadow password validator.
        // ==========================================================================

        require_once __DIR__ . '/../vendor/autoload.php';

        use UUP\Authentication\Authenticator\BasicHttpAuthenticator;
        use UUP\Authentication\Validator\ShadowValidator;

        try {
                $validator = new ShadowValidator();
                $authenticator = new BasicHttpAuthenticator($validator, "Shadow Password Authentication Example");
                $authenticator->message = "Logon cancelled by caller";
//                        $authenticator->redirect = basename(__FILE__);
//                        $validator->shadow = "/etc/apache2/shadow";

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
        }

        ?>
    </body>
</html>
