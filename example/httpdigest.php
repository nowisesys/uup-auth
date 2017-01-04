<!DOCTYPE html>
<!--
Copyright (C) 2014-2017 Anders Lövgren (QNET/BMC CompDept).

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
        <title>HTTP Digest Authentication</title>
    </head>
    <body>
        <h1>HTTP Digest Authentication</h1>
        <?php
        // ==========================================================================
        //  Example for HTTP Digest Authentication
        //  
        //  This example use an SQLite database as account source (for SQL validator)
        //  and session storage. The credentials for aauthentication is obtained
        //  using HTTP digest authentication.
        // ==========================================================================
        require_once __DIR__ . '/../vendor/autoload.php';

        use UUP\Authentication\Authenticator\DigestHttpAuthenticator;
        use UUP\Authentication\Storage\SqlStorage;
        use UUP\Authentication\Validator\PasswordProvider;
        use UUP\Authentication\Validator\SqlValidator;

        class DataValidator extends SqlValidator implements PasswordProvider
        {

                public function getPassword($user)
                {
                        $sql = sprintf("SELECT pass FROM users WHERE user = '%s'", $user);
                        return $this->query($sql)->fetchColumn();
                }

        }

        class DataStorage extends SqlStorage
        {

                public function setup()
                {
                        $this->exec("DROP TABLE IF EXISTS sessions");
                        $this->exec("DROP TABLE IF EXISTS users");
                        $this->exec("CREATE TABLE sessions(user varchar(10), logon TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)");
                        $this->exec("CREATE TABLE users(user varchar(10), pass varchar(10))");
                        $this->exec("INSERT INTO users(user, pass) VALUES('admin', 'admin')");
                }

        }

        try {
                $sqlite = sprintf("sqlite:/%s/%s.sql", sys_get_temp_dir(), basename(__FILE__));
                $objpdo = new PDO($sqlite, null, null);

                $validator = new DataValidator($objpdo);

                $authenticator = new DigestHttpAuthenticator($validator, "HTTP Digest Authentication Example");
                $authenticator->message = "Logon cancelled by caller";

                if (isset($_GET['login'])) {
                        $authenticator->login();
                }
                if (isset($_GET['logout'])) {
                        $authenticator->logout();
                }
                if (isset($_GET['create'])) {
                        $storage = new DataStorage($objpdo);
                        $storage->setup();
                }

                if ($authenticator->accepted()) {
                        printf("<p>Logged on as %s | <a href=\"?logout\">Logout</a>\n", $authenticator->getSubject());
                } else {
                        printf("<p><a href=\"?login\">Login</a>\n");
                }

                printf("<p>Use 'admin'/'admin' as username and password.</p>\n");
        } catch (Exception $exception) {
                printf("Exception: %s", $exception);
                printf("<p>Click <a href=\"?create\">create</a> to create the SQLite database.</p>\n");
        }

        ?>
        <hr>
    </body>
</html>
