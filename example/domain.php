<!DOCTYPE html>
<!--
Copyright (C) 2016 Anders Lövgren (QNET/BMC CompDept).

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
        <title>Domain Authentication</title>
    </head>
    <body>
        <h1>Domain Authentication</h1>
        <?php
        // ==========================================================================
        //  Domain authentication.
        //  
        //  Demonstrate using DomainAuthenticator class for authentication remote
        //  peer against domain name. The DomainAuthenticator class could be used
        //  for granting access to priviledged computers without requiring the user
        //  authentication.
        // ==========================================================================

        require_once __DIR__ . '/../vendor/autoload.php';

        use UUP\Authentication\Authenticator\DomainAuthenticator;

        $authenticator = new DomainAuthenticator('|^.*.(bmc.uu.se)$|');
        printf("<p>\n");
        printf("Name: %s<br>\n", $authenticator->getSubject());
        printf("Authenticated: %s<br>\n", $authenticator->accepted() ? "yes" : "no");
        printf("Domain: %s<br>\n", $authenticator->getDomain());
        printf("</p>\n");

        ?>
    </body>
</html>
