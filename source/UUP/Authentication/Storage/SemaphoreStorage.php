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

        const key_usage = 1;

        private $id;
        private $key;
        private $size;
        private $perm;

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

                $this->key = $key != 0 ? $key : self::genkey();
                $this->size = $size;
                $this->perm = $perm;

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
                return shm_has_var($this->id, self::hash($user));
        }

        public function insert($user)
        {
                shm_put_var($this->id, self::hash($user), $user);
        }

        public function remove($user)
        {
                shm_remove_var($this->id, self::hash($user));
        }

        private function open()
        {
                $this->id = shm_attach($this->key, $this->perm, $this->size);
        }

        private function close()
        {
                if ($this->usage() == 0) {
                        shm_remove($this->id);
                } else {
                        shm_detach($this->id);
                }
        }

        private function increment()
        {
                shm_put_var($this->id, self::key_usage, $this->usage() + 1);
        }

        private function decrement()
        {
                shm_put_var($this->id, self::key_usage, $this->usage() - 1);
        }

        private function usage()
        {
                return shm_get_var($this->id, self::key_usage);
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
