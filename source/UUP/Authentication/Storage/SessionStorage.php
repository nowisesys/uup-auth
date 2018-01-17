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

use Serializable;
use UUP\Authentication\Exception;
use UUP\Authentication\Library\Session\SessionAdapter;
use UUP\Authentication\Library\Session\SessionNative;
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

        /**
         * The session data.
         * @var object 
         */
        private $_data;

        /**
         * Constructor.
         */
        public function __construct()
        {
                $this->_data = (object) array();
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                $this->_data = null;
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

        /**
         * Serialize session data.
         * @return string
         */
        public function serialize()
        {
                return serialize((array) $this->_data);
        }

        /**
         * Unserialize session data.
         * @param string $serialized The serialized session data.
         */
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

        /**
         * Enforce session over HTTPS.
         * @var bool 
         */
        private $_https;
        /**
         * Check peer address.
         * @var bool 
         */
        private $_match;
        /**
         * The session data name.
         * @var string 
         */
        private $_name;
        /**
         * The expire time (timestamp).
         * @var int 
         */
        private $_expires = self::EXPIRES;
        /**
         * The session adapter.
         * @var SessionAdapter 
         */
        private $_session;

        /**
         * Constructor.
         * @param string $name The session data name.
         * @param bool $https Enforce session over HTTPS.
         * @param bool $match Require callers IP-address to match IP-address saved in session data.
         * @throws Exception
         */
        public function __construct($name = null, $https = true, $match = true, $session = false)
        {
                $this->_https = $https;
                $this->_match = $match;
                $this->_name = self::name($name);
                $this->_session = $session;

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

        /**
         * Check if storage contains user session.
         * @param string $user The username.
         * @return boolean
         */
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

        /**
         * Insert user session.
         * @param string $user The username.
         */
        public function insert($user)
        {
                $data = $this->read();
                $data->user = $user;
                $data->addr = $_SERVER['REMOTE_ADDR'];
                $data->expires = time() + $this->_expires;
                $this->save($data);
        }

        /**
         * Remove user session.
         * @param string $user The username.
         */
        public function remove($user)
        {
                $this->_session->start();
                unset($_SESSION[$this->_name]);
                $this->_session->close();
        }

        /**
         * Get session data.
         * @return SessionData
         */
        public function read()
        {
                $this->_session->start();
                $data = isset($_SESSION[$this->_name]) ? $_SESSION[$this->_name] : new SessionData();
                $this->_session->close();
                return $data;
        }

        /**
         * Save session data.
         * @param SessionData $data
         */
        private function save($data)
        {
                $this->_session->start();
                $_SESSION[$this->_name] = $data;
                $this->_session->close();
        }

        /**
         * Initialize session storage.
         * @throws Exception
         */
        private function initialize()
        {
                if ($this->_https && !isset($_SERVER['HTTPS'])) {
                        throw new Exception("HTTPS protocol is required");
                }
                if (!$this->_session) {
                        $this->_session = new SessionNative();
                }

                $this->_session->start();
                $this->_session->regenerate(true);
                $this->_session->close();
        }

        /**
         * Validate session data.
         * @param object $data The session data.
         * @throws Exception
         */
        private function sanitize($data)
        {
                if (isset($data->addr) && $data->addr != $_SERVER['REMOTE_ADDR']) {
                        throw new Exception("Remote address don't match session data (" . $data->addr . ").");
                }
        }

        /**
         * Generate session name.
         * @param string $name The session name (might be null).
         * @return string
         */
        private static function name($name)
        {
                return isset($name) ? $name : strtolower(basename(__FILE__) . __LINE__);
        }

}
