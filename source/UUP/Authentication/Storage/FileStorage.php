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

/**
 * Implements storage in file system.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class FileStorage implements Storage
{

        /**
         * The filename.
         * @var string 
         */
        private $_file;

        /**
         * Constructor.
         * @param string $file The filename path.
         */
        public function __construct($file)
        {
                $this->_file = $file;
        }

        /**
         * Check if user exists.
         * @param string $user The username.
         * @return boolean
         */
        public function exist($user)
        {
                $data = $this->read();
                return array_key_exists($user, $data);
        }

        /**
         * Insert user in storage.
         * @param string $user The username.
         * @return boolean
         */
        public function insert($user)
        {
                $data = $this->read();
                $data[$user] = time();
                $this->write($data);
                return true;
        }

        /**
         * Remove user from storage.
         * @param string $user The username.
         * @return boolean
         */
        public function remove($user)
        {
                $data = $this->read();
                unset($data[$user]);
                $this->write($data);
                return true;
        }

        /**
         * Read file storage.
         * @return array
         */
        private function read()
        {
                return (array) unserialize(file_get_contents($this->_file));
        }

        /**
         * Write file storage.
         * @param array $data The storage data.
         */
        private function write($data)
        {
                file_put_contents($this->_file, serialize($data));
        }

}
