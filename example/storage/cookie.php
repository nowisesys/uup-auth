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
        <title>Cookie Storage Test</title>
    </head>
    <body>
        <h1>Cookie Storage Test</h1>
        <?php
        // ==========================================================================
        //  Simple test of cookie storage.
        // ==========================================================================

        require_once __DIR__ . '/../../vendor/autoload.php';

        use UUP\Authentication\Storage\CookieStorage;

        $user = 'test';

        try {

                $cookie = new CookieStorage();

                if (isset($_REQUEST['remove'])) {
                        $cookie->remove($user);
                        header(sprintf("Location: %s", $_SERVER['HTTP_REFERER']));
                }
                if (isset($_REQUEST['insert'])) {
                        $cookie->insert($user);
                        header(sprintf("Location: %s", $_SERVER['HTTP_REFERER']));
                }

                if ($cookie->exist($user)) {
                        printf("<p>Cookie exist for user %s | <a href=\"?remove\">Remove</a></p>\n", $user);
                } else {
                        printf("<p>No cookie exist | <a href=\"?insert\">Insert</a></p>\n");
                }
        } catch (Exception $exception) {
                printf("Exception: %s", $exception);
        }

        ?>
    </body>
</html>
