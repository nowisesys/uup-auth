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
                <title>CAS Authentication</title>
        </head>
        <body>
                <h1>CAS Authentication</h1>
                <?php
                require_once __DIR__ . '/../vendor/autoload.php';

                use UUP\Authentication\CasAuthenticator;

                $host = "cas.example.com";
                $port = 443;
                $path = "/cas";

                $authenticator = new CasAuthenticator($host, $port, $path);

                if ($authenticator->authenticated()) {
                        printf("<p>Logged on as %s | <a href=\"?logout\">Logout</a>\n", $authenticator->getUser());
                } else {
                        printf("<p><a href=\"?login\">Login</a>\n");
                }

                if (isset($_GET['login'])) {
                        $authenticator->login();
                }
                if (isset($_GET['logout'])) {
                        $authenticator->logout();
                }

                ?>
        </body>
</html>
