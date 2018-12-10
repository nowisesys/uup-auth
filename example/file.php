<!DOCTYPE html>
<!--
Copyright (C) 2017 Anders Lövgren (Nowise Systems/Uppsala University).

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
        <title>Simple File Authentication Example</title>
    </head>
    <body>
        <h1>Simple File Authentication Example</h1>
        <?php
        // ==========================================================================
        //  Text file authentication.
        // ==========================================================================

        require_once __DIR__ . '/../vendor/autoload.php';

        use UUP\Authentication\Authenticator\BasicHttpAuthenticator;
        use UUP\Authentication\Validator\FileValidator;

try {
                $filename = sprintf("%s/file.ser", sys_get_temp_dir());

                if (!file_exists($filename)) {
                        if (file_put_contents($filename, serialize(array(
                                    "admin" => "admin",
                                    "user"  => "secret"
                            )))) {
                                printf("Created %s user/pass file\n", $filename);
                        } else {
                                throw new RuntimeException("Failed create $filename");
                        }
                }

                $validator = new FileValidator($filename);
                $authenticator = new BasicHttpAuthenticator($validator, "File Authentication Example");
                $authenticator->message = "Logon cancelled by caller";

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
