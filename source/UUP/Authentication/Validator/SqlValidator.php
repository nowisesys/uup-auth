<?php

/*
 * Copyright (C) 2014 Anders Lövgren (QNET/BMC CompDept).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace UUP\Authentication\Validator;

use UUP\Authentication\Storage\SqlConnector;

/**
 * Validate usera agains an SQL database table.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class SqlValidator extends CredentialValidator
{

        use SqlConnector {
                initialize as private;
        }

        const table = "users";
        const fuser = "user";
        const fpass = "pass";

        /**
         * Constructor.
         * @param PDO $pdo The database connection object.
         * @param string $table The user account table name.
         * @param string $fuser The username column (field) name.
         * @param string $fpass The password column (field) name.
         * @throws Exception
         */
        public function __construct($pdo, $table = self::table, $fuser = self::fuser, $fpass = self::fpass)
        {
                $this->initialize($pdo, $table, $fuser, $fpass);
        }

        public function authenticate()
        {
                $sql = sprintf("SELECT COUNT(*) FROM %s WHERE %s = '%s' AND %s = '%s'", $this->table, $this->fuser, $this->user, $this->fpass, $this->pass);
                return $this->query($sql)->fetchColumn() > 0;
        }

}
