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

namespace UUP\Authentication\Storage;

use PDO;
use UUP\Authentication\Exception;
use UUP\Authentication\Storage\Storage;

/**
 * SQL session storage backend.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class SqlStorage implements Storage
{

        use \UUP\Authentication\Library\Connector\SqlConnector {
                initialize as private;
        }

        /**
         * The default session table name.
         */
        const TABLE = "sessions";
        /**
         * The default session user field name.
         */
        const FUSER = "user";

        /**
         * Constructor.
         * @param PDO $pdo The database connection object.
         * @param string $table The logon session table name.
         * @param string $fuser The username column (field) name.
         * @throws Exception
         */
        public function __construct($pdo, $table = self::TABLE, $fuser = self::FUSER)
        {
                $this->initialize($pdo, $table, $fuser, "");
        }
        
        /**
         * Destructor.
         */
        public function __destruct()
        {
                $this->cleanup();
        }

        /**
         * Check if user exists in storage.
         * @param string $user The username.
         * @return boolean
         */
        public function exist($user)
        {
                $sql = sprintf("SELECT COUNT(*) FROM %s WHERE %s = '%s'", $this->_table, $this->_fuser, $user);
                return $this->query($sql)->fetchColumn() > 0;
        }

        /**
         * Insert user in storage.
         * @param string $user The username.
         * @return boolean
         */
        public function insert($user)
        {
                $sql = sprintf("INSERT INTO %s(%s) VALUES('%s')", $this->_table, $this->_fuser, $user);
                return $this->exec($sql) !== 0;
        }

        /**
         * Remove user from storage.
         * @param string $user The username.
         * @return boolean
         */
        public function remove($user)
        {
                $sql = sprintf("DELETE FROM %s WHERE %s = '%s'", $this->_table, $this->_fuser, $user);
                return $this->exec($sql) !== 0;
        }

}
