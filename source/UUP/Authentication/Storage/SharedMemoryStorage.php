<?php

/*
 * Copyright (C) 2014-2015 Anders Lövgren (Nowise Systems/Uppsala University).
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
 * @author Anders Lövgren (Nowise Systems/Uppsala University)
 * @package UUP
 * @subpackage Authentication
 */
class SharedMemoryStorage implements Storage
{

        /**
         * Create shared memory if missing.
         */
        const OPEN_CREATE = "c";
        /**
         * Open shared memory on read/write mode.
         */
        const OPEN_READWR = "w";
        /**
         * Reserved for usage count.
         */
        const OFFSET = 5;
        /**
         * The default shared memory size.
         */
        const SIZE = 10000;
        /**
         * The default create file permission.
         */
        const MODE = 0644;

        /**
         * The shared memory handle.
         * @var resource 
         */
        private $_id;
        /**
         * The shared memory segment key.
         * @var string
         */
        private $_key;
        /**
         * The open flags.
         * @var int 
         */
        private $_flags;
        /**
         * The permissions.
         * @var int 
         */
        private $_mode;
        /**
         * The current size (grows as needed).
         * @var int 
         */
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

        /**
         * Check if key exists.
         * @param string $user The username.
         * @return boolean
         */
        public function exist($user)
        {
                $data = $this->read();
                return array_key_exists($user, $data);
        }

        /**
         * Inserts user entry.
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
         * Remove user entry.
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
         * Open shared memory segment.
         * @throws Exception
         */
        private function open()
        {
                if (!($this->_id = @shmop_open($this->_key, $this->_flags, $this->_mode, $this->_size))) {
                        $this->_flags = self::OPEN_CREATE;
                }
                if (!($this->_id = @shmop_open($this->_key, $this->_flags, $this->_mode, $this->_size))) {
                        throw new Exception("Failed open shared memory segment");
                }
        }

        /**
         * Close shared memory segment.
         * The memory segment will be deleted when usage count drops to zero.
         */
        private function close()
        {
                if ($this->usage() == 0) {
                        shmop_delete($this->_id);
                } else {
                        shmop_close($this->_id);
                }
        }

        /**
         * Read shared memory segment.
         * @return array
         * @throws Exception
         */
        private function read()
        {
                if (!($data = shmop_read($this->_id, self::OFFSET, $this->_size - self::OFFSET))) {
                        throw new Exception("Failed read shared memory");
                } else {
                        return (array) unserialize(trim($data));
                }
        }

        /**
         * Write shared memory segment.
         * @param array $array The data to write.
         * @throws Exception
         */
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

        /**
         * Resize the shared memory segment.
         * @param int $size New memory size.
         */
        private function realloc($size)
        {
                $data = $this->read();
                $this->close();
                $this->_size = $size;
                $this->open();
                $this->write($data);
        }

        /**
         * Increment usage count.
         */
        private function increment()
        {
                $count = $this->usage();
                shmop_write($this->_id, $count + 1, 0);
        }

        /**
         * Decrement usage count.
         */
        private function decrement()
        {
                $count = $this->usage();
                shmop_write($this->_id, $count - 1, 0);
        }

        /**
         * Get current usage count.
         * @return int
         * @throws Exception
         */
        private function usage()
        {
                if (!($count = shmop_read($this->_id, 0, self::OFFSET))) {
                        throw new Exception("Failed read shared memory");
                } else {
                        return (int) $count;
                }
        }

        /**
         * Generate shared memory key.
         * 
         * The key is generated by calling ftok that converts a pathname (current file) and a 
         * project identifier (a fixed string) to a System V IPC key.
         * 
         * @return string
         */
        private static function genkey()
        {
                return ftok(__FILE__, "a");
        }

}
