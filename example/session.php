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
                <title>Session Storage Test</title>
        </head>
        <body>
                <?php
                // ==========================================================================
                //  Simple test of session storage.
                // ==========================================================================

                require_once __DIR__ . '/../vendor/autoload.php';

                use UUP\Authentication\Storage\SessionStorage;

                $user = 'test';
                $name = 'mysession';

                try {

                        $session = new SessionStorage($name, false, false);

                        printf("<h1>Session Storage Test</h1>\n");

                        if (isset($_REQUEST['remove'])) {
                                $session->remove($user);
                        }
                        if (isset($_REQUEST['insert'])) {
                                $session->insert($user);
                        }

                        if ($session->exist($user)) {
                                printf("<p>Session exist for user %s | <a href=\"?remove\">Remove</a></p>\n", $user);
                        } else {
                                printf("<p>No session exist | <a href=\"?insert\">Insert</a></p>\n");
                        }
                } catch (\Exception $exception) {
                        printf("Exception: %s", $exception);
                }

                ?>
        </body>
</html>
