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

use UUP\Authentication\Exception;
use UUP\Authentication\Storage\Storage;

/**
 * Storage using shared memory. This class uses the sysvshm extension.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class SemaphoreStorage implements Storage
{

        const KEY_USAGE = 1;

        private $_id;
        private $_key;
        private $_size;
        private $_perm;

        /**
         * Constructor.
         * @param int $key The shared memory key.
         * @param int $size The shared memory size. Defaults to sysvshm.init_mem in php.ini
         * @param int $perm The permission bits.
         * @throws Exception
         */
        public function __construct($key = 0, $size = null, $perm = 0666)
        {
                if (!extension_loaded('sysvshm')) {
                        throw new Exception("The sysvshm extension is not loaded.");
                }

                $this->_key = $key != 0 ? $key : self::genkey();
                $this->_size = $size;
                $this->_perm = $perm;

                $this->open();
                $this->increment();
        }

        /**
         * Destructor. Removes the shared memory segment if usage count drops to zero.
         */
        public function __destruct()
        {
                $this->decrement();
                $this->close();
        }

        public function exist($user)
        {
                return shm_has_var($this->_id, self::hash($user));
        }

        public function insert($user)
        {
                shm_put_var($this->_id, self::hash($user), $user);
        }

        public function remove($user)
        {
                shm_remove_var($this->_id, self::hash($user));
        }

        private function open()
        {
                $this->_id = shm_attach($this->_key, $this->_perm, $this->_size);
        }

        private function close()
        {
                if ($this->usage() == 0) {
                        shm_remove($this->_id);
                } else {
                        shm_detach($this->_id);
                }
        }

        private function increment()
        {
                shm_put_var($this->_id, self::KEY_USAGE, $this->usage() + 1);
        }

        private function decrement()
        {
                shm_put_var($this->_id, self::KEY_USAGE, $this->usage() - 1);
        }

        private function usage()
        {
                return shm_get_var($this->_id, self::KEY_USAGE);
        }

        private static function genkey()
        {
                return ftok(__FILE__, "a");
        }

        private static function hash($str)
        {
                return base_convert(md5($str), 16, 10);
        }

}
