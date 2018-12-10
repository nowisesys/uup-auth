<?php

/*
 * Copyright (C) 2014-2016 Anders Lövgren (Nowise Systems/Uppsala University).
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

namespace UUP\Authentication\Library\Connector;

use PDO;
use UUP\Authentication\Exception;

/**
 * Common base class for SQL session storage and validator.
 *
 * @author Anders Lövgren (Nowise Systems/Uppsala University)
 * @package UUP
 * @subpackage Authentication
 */
trait SqlConnector
{

        /**
         * The database connection.
         * @var PDO 
         */
        private $_pdo;
        /**
         * The table name.
         * @var string 
         */
        protected $_table;
        /**
         * The username field name.
         * @var string 
         */
        protected $_fuser;
        /**
         * The password field name.
         * @var string 
         */
        protected $_fpass;

        /**
         * Constructor.
         * @param PDO $pdo The database connection object.
         * @param string $table The table name.
         * @param string $fuser The username column (field) name.
         * @param string $fpass The password column (field) name.
         * @throws Exception
         */
        public function initialize($pdo, $table, $fuser, $fpass)
        {
                if (!extension_loaded('PDO')) {
                        throw new Exception("The PDO extension is not loaded.");
                }
                $this->_pdo = $pdo;
                $this->_table = $table;
                $this->_fuser = $fuser;
                $this->_fpass = $fpass;
        }

        /**
         * Execute SQL query.
         * 
         * @param string $sql The SQL string.
         * @return PDOStatement
         * @throws Exception
         */
        protected function query($sql)
        {
                if (!($res = $this->_pdo->query($sql))) {
                        $error = $this->_pdo->errorInfo();
                        throw new Exception(sprintf("Failed query database: %s", $error[2]));
                } else {
                        return $res;
                }
        }

        /**
         * Execute SQL statement.
         * 
         * @param string $sql The SQL string.
         * @return int The number of rows that were modified or deleted
         */
        protected function exec($sql)
        {
                return $this->_pdo->exec($sql);
        }

        /**
         * Cleanup routine.
         */
        protected function cleanup()
        {
                $this->_fpass = null;
                $this->_fuser = null;
                $this->_table = null;
                $this->_pdo = null;
        }

}
