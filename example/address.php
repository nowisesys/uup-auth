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
                <title>IP-Address Authentication</title>
        </head>
        <body>
                <h1>IP-Address Authentication</h1>
                <?php
                require_once __DIR__ . '/../vendor/autoload.php';

                use UUP\Authentication\AddressAuthenticator;

                $authenticator = new AddressAuthenticator();
                // $authenticator->add('192.168.45.67');
                // $authenticator->clear();
                printf("<p>\n");
                printf("IP-Address: %s<br>\n", $authenticator->getUser());
                printf("Authenticated: %s<br>\n", $authenticator->authenticated() ? "yes" : "no");
                printf("</p>\n");

                ?>
        </body>
</html>