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
 * The session data. 
 * 
 * This class implements the Serializable interface so it can be used direct 
 * with PHP's global session variable.
 * 
 * @property string $user The username.
 * @property string $addr The associated IP-address.
 * @property int $expires The expiration timestamp.
 */
class SessionData implements \Serializable
{

        private $data;

        public function __construct()
        {
                $this->data = (object) array();
        }

        public function __get($name)
        {
                if (isset($this->data->$name)) {
                        return $this->data->$name;
                }
        }

        public function __set($name, $value)
        {
                $this->data->$name = $value;
        }

        public function serialize()
        {
                return serialize((array) $this->data);
        }

        public function unserialize($serialized)
        {
                $this->data = (object) unserialize($serialized);
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
        const expires = 7200;

        private $https;
        private $match;
        private $name;
        private $expires = self::expires;

        /**
         * Constructor.
         * @param string $name The session data name.
         * @param bool $https Enforce session over HTTPS.
         * @param bool $match Require callers IP-address to match IP-address saved in session data.
         * @throws Exception
         */
        public function __construct($name = null, $https = true, $match = true)
        {
                $this->https = $https;
                $this->match = $match;
                $this->name = self::name($name);

                $this->initialize();
        }

        public function __get($name)
        {
                switch ($name) {
                        case 'expires':
                                return $this->expires;
                        case 'https':
                                return $this->https;
                        case 'match':
                                return $this->match;
                }
        }

        public function __set($name, $value)
        {
                switch ($name) {
                        case 'expires':
                                $this->expires = (int) $value;
                                break;
                        case 'https':
                                $this->https = (bool) $value;
                                break;
                        case 'match':
                                $this->match = (bool) $value;
                }
        }

        public function exist($user)
        {
                $data = $this->read();
                if ($this->match) {
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
                $data->expires = time() + $this->expires;
                $this->save($data);
        }

        public function remove($user)
        {
                session_start();
                unset($_SESSION[$this->name]);
                session_write_close();
        }

        /**
         * Get session data.
         * @return SessionData
         */
        public function read()
        {
                session_start();
                $data = isset($_SESSION[$this->name]) ? $_SESSION[$this->name] : new SessionData();
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
                $_SESSION[$this->name] = $data;
                session_write_close();
        }

        private function initialize()
        {
                if ($this->https && !isset($_SERVER['HTTPS'])) {
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
