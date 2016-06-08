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
 * Storage using shared memory. This class uses the shmop extension.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class SharedMemoryStorage implements Storage
{

        const OPEN_CREATE = "c";
        const OPEN_READWR = "w";
        const OFFSET = 5;     // reserved for usage count
        const SIZE = 10000;
        const MODE = 0644;

        private $_id;
        private $_key;
        private $_flags;
        private $_mode;
        private $_size;

        /**
         * Constructor.
         * @param int $key The shared memory segment key.
         * @param string $flags The open flags.
         * @param int $mode The permissions assigned to the shared memory segment.
         * @param int $size The initial segment size. Grown as needed.
         * @throws Exception
         */
        public function __construct($key = 0, $flags = self::OPEN_READWR, $mode = self::MODE, $size = self::SIZE)
        {
                if (!extension_loaded('shmop')) {
                        throw new Exception("The shmop extension is not loaded.");
                }

                $this->_key = $key != 0 ? $key : self::genkey();
                $this->_flags = $flags;
                $this->_mode = $mode;
                $this->_size = $size;

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
                if (!($this->_id = @shmop_open($this->_key, $this->_flags, $this->_mode, $this->_size))) {
                        $this->_flags = self::OPEN_CREATE;
                }
                if (!($this->_id = @shmop_open($this->_key, $this->_flags, $this->_mode, $this->_size))) {
                        throw new Exception("Failed open shared memory segment");
                }
        }

        private function close()
        {
                if ($this->usage() == 0) {
                        shmop_delete($this->_id);
                } else {
                        shmop_close($this->_id);
                }
        }

        private function read()
        {
                if (!($data = shmop_read($this->_id, self::OFFSET, $this->_size - self::OFFSET))) {
                        throw new Exception("Failed read shared memory");
                } else {
                        return (array) unserialize(trim($data));
                }
        }

        private function write($array)
        {
                $data = serialize($array);
                $size = strlen($data);

                if ($size > $this->_size) {
                        $this->realloc($size * 2);
                }

                if (!(shmop_write($this->_id, $data, self::OFFSET))) {
                        throw new Exception("Failed write shared memory");
                }
        }

        private function realloc($size)
        {
                $data = $this->read();
                $this->close();
                $this->_size = $size;
                $this->open();
                $this->write($data);
        }

        private function increment()
        {
                $count = $this->usage();
                shmop_write($this->_id, $count + 1, 0);
        }

        private function decrement()
        {
                $count = $this->usage();
                shmop_write($this->_id, $count - 1, 0);
        }

        private function usage()
        {
                if (!($count = shmop_read($this->_id, 0, self::OFFSET))) {
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
