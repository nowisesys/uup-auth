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
                <title>Hostname Authentication</title>
        </head>
        <body>
                <h1>Hostname Authentication</h1>
                <?php

                // ==========================================================================
                //  Hostname authentication.
                //  
                //  Demonstrate using HostnameAuthenticator class for authentication remote
                //  peer based on its DNS-name. The HostnameAuthenticator class could be used
                //  for granting access to priviledged computers without requiring the user
                //  authentication.
                // ==========================================================================
                
                require_once __DIR__ . '/../vendor/autoload.php';

                use UUP\Authentication\Authenticator\HostnameAuthenticator;

                $authenticator = new HostnameAuthenticator();
                // $authenticator->setHostname('hostname');
                printf("<p>\n");
                printf("Name: %s<br>\n", $authenticator->getSubject());
                printf("Authenticated: %s<br>\n", $authenticator->accepted() ? "yes" : "no");
                printf("</p>\n");

                ?>
        </body>
</html>
