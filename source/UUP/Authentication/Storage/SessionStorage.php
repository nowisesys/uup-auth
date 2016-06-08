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

use Serializable;
use UUP\Authentication\Exception;
use UUP\Authentication\Storage\SessionData;
use UUP\Authentication\Storage\Storage;

/**
 * The session data. 
 * 
 * This class implements the Serializable interface so it can be used direct 
 * with PHP's global session variable.
 * 
 * @property string $user The username.
 * @property string $addr The associated IP-address.
 * @property int $expires The expiration timestamp.
 */
class SessionData implements Serializable
{

        private $_data;

        public function __construct()
        {
                $this->_data = (object) array();
        }

        public function __get($name)
        {
                if (isset($this->_data->$name)) {
                        return $this->_data->$name;
                }
        }

        public function __set($name, $value)
        {
                $this->_data->$name = $value;
        }

        public function serialize()
        {
                return serialize((array) $this->_data);
        }

        public function unserialize($serialized)
        {
                $this->_data = (object) unserialize($serialized);
        }

}

/**
 * Storage using PHP session. 
 * 
 * The session data is represented by a SessionData object that is stored on the
 * server side. The session data keeps track of remote peer (recorded in the
 * session data object) and verify that the remote caller is the same (prevent 
 * session hijack).
 * 
 * @property int $expires The session length in seconds. Dynamic when exist() gets called.
 * @property bool $https Enforce HTTPS protocol for session.
 * @property bool $match Require peer address to match recorded session data address.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 * 
 * @see SessionData
 */
class SessionStorage implements Storage
{

        /**
         * Number of seconds until an session expires if not being refreshed.
         */
        const EXPIRES = 7200;

        private $_https;
        private $_match;
        private $_name;
        private $_expires = self::EXPIRES;

        /**
         * Constructor.
         * @param string $name The session data name.
         * @param bool $https Enforce session over HTTPS.
         * @param bool $match Require callers IP-address to match IP-address saved in session data.
         * @throws Exception
         */
        public function __construct($name = null, $https = true, $match = true)
        {
                $this->_https = $https;
                $this->_match = $match;
                $this->_name = self::name($name);

                $this->initialize();
        }

        public function __get($name)
        {
                switch ($name) {
                        case 'expires':
                                return $this->_expires;
                        case 'https':
                                return $this->_https;
                        case 'match':
                                return $this->_match;
                }
        }

        public function __set($name, $value)
        {
                switch ($name) {
                        case 'expires':
                                $this->_expires = (int) $value;
                                break;
                        case 'https':
                                $this->_https = (bool) $value;
                                break;
                        case 'match':
                                $this->_match = (bool) $value;
                }
        }

        public function exist($user)
        {
                $data = $this->read();
                if ($this->_match) {
                        $this->sanitize($data);
                }
                if ($data->expires < time()) {
                        $this->remove($user);
                        return false;
                }
                return $data->user == $user;
        }

        public function insert($user)
        {
                $data = $this->read();
                $data->user = $user;
                $data->addr = $_SERVER['REMOTE_ADDR'];
                $data->expires = time() + $this->_expires;
                $this->save($data);
        }

        public function remove($user)
        {
                session_start();
                unset($_SESSION[$this->_name]);
                session_write_close();
        }

        /**
         * Get session data.
         * @return SessionData
         */
        public function read()
        {
                session_start();
                $data = isset($_SESSION[$this->_name]) ? $_SESSION[$this->_name] : new SessionData();
                session_write_close();
                return $data;
        }

        /**
         * Save session data.
         * @param SessionData $data
         */
        private function save($data)
        {
                session_start();
                $_SESSION[$this->_name] = $data;
                session_write_close();
        }

        private function initialize()
        {
                if ($this->_https && !isset($_SERVER['HTTPS'])) {
                        throw new Exception("HTTPS protocol is required");
                }

                session_start();
                session_regenerate_id(true);
                session_write_close();
        }

        private function sanitize($data)
        {
                if (isset($data->addr) && $data->addr != $_SERVER['REMOTE_ADDR']) {
                        throw new Exception("Remote address don't match session data (" . $data->addr . ").");
                }
        }

        private static function name($name)
        {
                return isset($name) ? $name : strtolower(basename(__FILE__) . __LINE__);
        }

}
