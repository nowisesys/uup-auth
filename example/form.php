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
                <title>Form Authentication Example</title>
        </head>
        <body>
                <h1>Form Authentication Example</h1>
                <?php
                // ==========================================================================
                //  HTML form authentication.
                // ==========================================================================

                require_once __DIR__ . '/../vendor/autoload.php';

use UUP\Authentication\Validator\ShadowValidator;
use UUP\Authentication\FormAuthenticator;

try {
                        $validator = new ShadowValidator();
                        $authenticator = new FormAuthenticator($validator, array(
                                'login' => '?showform',
                                'name'  => 'pname',
                                'user'  => 'puser',
                                'pass'  => 'ppass'
                        ));

                        if (isset($_GET['login'])) {
                                $authenticator->login();
                        }
                        if (isset($_GET['logout'])) {
                                $authenticator->logout();
                        }
                        if (isset($_GET['showform'])) {
                                printf("<form action='%s' method='POST'>\n", $authenticator->return);
                                printf("<label for='%s'>Username:</label>\n", $authenticator->user);
                                printf("<input name='%s' type='text' />\n", $authenticator->user);
                                printf("<label for='%s'>Password:</label>\n", $authenticator->pass);
                                printf("<input name='%s' type='password' />\n", $authenticator->pass);
                                printf("<label for='%s' />\n", $authenticator->name);
                                printf("<input name='%s' type='submit' value='Login'>\n", $authenticator->name);
                                printf("</form>\n");
                        }

                        if ($authenticator->authenticated()) {
                                printf("<p>Logged on as %s | <a href=\"?logout\">Logout</a>\n", $authenticator->getUser());
                        } else {
                                printf("<p><a href=\"?login\">Login</a>\n");
                        }

                        printf("<p>Use a system user account for login.</p>\n");
                } catch (\Exception $exception) {
                        printf("Exception: %s", $exception);
                }

                ?>
        </body>
</html>
