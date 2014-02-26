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
 * Storage using shared memory. This class uses the shmop extension.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class SharedMemoryStorage implements Storage
{

        const open_create = "c";
        const open_readwr = "w";
        const offset = 5;     // reserved for usage count
        const size = 10000;
        const mode = 0644;

        private $id;
        private $key;
        private $flags;
        private $mode;
        private $size;

        /**
         * Constructor.
         * @param int $key The shared memory segment key.
         * @param string $flags The open flags.
         * @param int $mode The permissions assigned to the shared memory segment.
         * @param int $size The initial segment size. Grown as needed.
         * @throws Exception
         */
        public function __construct($key = 0, $flags = self::open_readwr, $mode = self::mode, $size = self::size)
        {
                if (!extension_loaded('shmop')) {
                        throw new Exception("The shmop extension is not loaded.");
                }

                $this->key = $key != 0 ? $key : self::genkey();
                $this->flags = $flags;
                $this->mode = $mode;
                $this->size = $size;

                $this->open();
                $this->increment();
        }

        /**
         * Destructor. Deletes the shared memory segment if usage count drops to zero.
         */
        public function __destruct()
        {
                $this->decrement();
                $this->close();
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

        private function open()
        {
                if (!($this->id = @shmop_open($this->key, $this->flags, $this->mode, $this->size))) {
                        $this->flags = self::open_create;
                }
                if (!($this->id = @shmop_open($this->key, $this->flags, $this->mode, $this->size))) {
                        throw new Exception("Failed open shared memory segment");
                }
        }

        private function close()
        {
                if ($this->usage() == 0) {
                        shmop_delete($this->id);
                } else {
                        shmop_close($this->id);
                }
        }

        private function read()
        {
                if (!($data = shmop_read($this->id, self::offset, $this->size - self::offset))) {
                        throw new Exception("Failed read shared memory");
                } else {
                        return (array) unserialize(trim($data));
                }
        }

        private function write($array)
        {
                $data = serialize($array);
                $size = strlen($data);

                if ($size > $this->size) {
                        $this->realloc($size * 2);
                }

                if (!(shmop_write($this->id, $data, self::offset))) {
                        throw new Exception("Failed write shared memory");
                }
        }

        private function realloc($size)
        {
                $data = $this->read();
                $this->close();
                $this->size = $size;
                $this->open();
                $this->write($data);
        }

        private function increment()
        {
                $count = $this->usage();
                shmop_write($this->id, $count + 1, 0);
        }

        private function decrement()
        {
                $count = $this->usage();
                shmop_write($this->id, $count - 1, 0);
        }

        private function usage()
        {
                if (!($count = shmop_read($this->id, 0, self::offset))) {
                        throw new Exception("Failed read shared memory");
                } else {
                        return (int) $count;
                }
        }

        private static function genkey()
        {
                return ftok(__FILE__, "a");
        }

}
