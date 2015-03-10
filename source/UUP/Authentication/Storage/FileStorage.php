<?php

/*
 * Copyright (C) 2014-2015 Anders Lövgren (QNET/BMC CompDept).
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

        private $file;

        public function __construct($file)
        {
                $this->file = $file;
        }

        public function exist($user)
        {
                $data = $this->read();
                return key_exists($user, $data);
        }

        public function insert($user)
        {
                $data = $this->read();
                $data[$user] = time();
                $this->write($data);
                return true;
        }

        public function remove($user)
        {
                $data = $this->read();
                unset($data[$user]);
                $this->write($data);
                return true;
        }

        private function read()
        {
                return (array) unserialize(file_get_contents($this->file));
        }

        private function write($data)
        {
                file_put_contents($this->file, serialize($data));
        }

}
