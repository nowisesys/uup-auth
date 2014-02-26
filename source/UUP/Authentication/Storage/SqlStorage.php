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

namespace UUP\Authentication\Storage;

use UUP\Authentication\Exception;

/**
 * SQL storage backend.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class SqlStorage implements Storage
{

        /**
         * @var PDO The database connection.
         */
        private $pdo;
        private $table;
        private $field;

        /**
         * Constructor.
         * @param PDO $pdo The database connection object.
         * @param string $table The user sessions table name.
         * @param string $field The table column (field) name.
         * @throws Exception
         */
        public function __construct($pdo, $table = "sessions", $field = "user")
        {
                if (!extension_loaded('PDO')) {
                        throw new Exception("The PDO extension is not loaded.");
                }
                $this->pdo = $pdo;
                $this->table = $table;
                $this->field = $field;
        }

        public function exist($user)
        {
                $sql = sprintf("SELECT COUNT(*) FROM %s WHERE %s = '%s'", $this->table, $this->field, $user);
                return $this->query($sql)->fetchColumn() > 0;
        }

        public function insert($user)
        {
                $sql = sprintf("INSERT INTO %s(%s) VALUES('%s')", $this->table, $this->field, $user);
                return $this->exec($sql) !== 0;
        }

        public function remove($user)
        {
                $sql = sprintf("DELETE FROM %s WHERE %s = '%s'", $this->table, $this->field, $user);
                return $this->exec($sql) !== 0;
        }

        private function query($sql)
        {
                if (!($res = $this->pdo->query($sql))) {
                        $error = $this->pdo->errorInfo();
                        throw new Exception(sprintf("Failed query database: %s", $error[2]));
                } else {
                        return $res;
                }
        }

        private function exec($sql)
        {
                return $this->pdo->exec($sql);
        }

}
