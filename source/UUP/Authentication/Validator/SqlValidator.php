<?php

/*
 * Copyright (C) 2014-2016 Anders Lövgren (QNET/BMC CompDept).
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

use PDO;
use UUP\Authentication\Exception;
use UUP\Authentication\Validator\CredentialValidator;

/**
 * Validate usera agains an SQL database table.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class SqlValidator extends CredentialValidator
{

        use \UUP\Authentication\Library\Connector\SqlConnector {
                initialize as private;
        }

        /**
         * The default users table name.
         */
        const TABLE = "users";
        /**
         * The default username field name.
         */
        const FUSER = "user";
        /**
         * The default password field name.
         */
        const FPASS = "pass";

        /**
         * Constructor.
         * @param PDO $pdo The database connection object.
         * @param string $table The user account table name.
         * @param string $fuser The username column (field) name.
         * @param string $fpass The password column (field) name.
         * @throws Exception
         */
        public function __construct($pdo, $table = self::TABLE, $fuser = self::FUSER, $fpass = self::FPASS)
        {
                parent::__construct();
                $this->initialize($pdo, $table, $fuser, $fpass);
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                parent::__destruct();
                $this->cleanup();       // traits
        }

        /**
         * Check credentials in storage.
         * @return boolean
         */
        public function authenticate()
        {
                $sql = sprintf("SELECT COUNT(*) FROM %s WHERE %s = '%s' AND %s = '%s'", $this->_table, $this->_fuser, $this->_user, $this->_fpass, $this->_pass);
                return $this->query($sql)->fetchColumn() > 0;
        }

}
