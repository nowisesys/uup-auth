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
use UUP\Authentication\Storage\CookieData;
use UUP\Authentication\Storage\Storage;

/**
 * The cookie data. 
 * 
 * @property string $hash The cryptographic hash.
 * @property string $user The username.
 * @property string $addr The associated IP-address.
 * @property int $expires The expiration timestamp.
 */
class CookieData implements Serializable
{

        /**
         * The cookie data.
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

        /**
         * Get value of key.
         * @param string $name The key name.
         * @return mixed
         */
        public function __get($name)
        {
                if (isset($this->_data->$name)) {
                        return $this->_data->$name;
                }
        }

        /**
         * Set key value.
         * @param string $name The key name.
         * @param mixed $value The value.
         */
        public function __set($name, $value)
        {
                $this->_data->$name = $value;
        }

        /**
         * Serialize storage data.
         * @return string
         */
        public function serialize()
        {
                return base64_encode(serialize((array) $this->_data));
        }

        /**
         * Unserialize storage data.
         * @param string $serialized The serialized data.
         */
        public function unserialize($serialized)
        {
                $this->_data = (object) unserialize(base64_decode($serialized));
        }

}

/**
 * Storage using HTTP cookie.
 *
 * Save username on remote host using cookies. The cookie is protected by a hash
 * value computed on username, remote address and expire time triple combined with
 * a user supplied key. The key is only known on the server side, making it hard
 * to reproduce a fake login session (cookie) on the client side.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class CookieStorage implements Storage
{

        /**
         * The encryption key.
         * @var string 
         */
        private $_key;
        /**
         * The name of the cookie.
         * @var string 
         */
        private $_name;
        /**
         * The expire time.
         * @var int 
         */
        private $_expire;
        /**
         * The cookie path.
         * @var string 
         */
        private $_path;
        /**
         * The cookie domain.
         * @var string 
         */
        private $_domain;
        /**
         * Use secure cookie (HTTPS only).
         * @var boolean 
         */
        private $_secure;
        /**
         * Only accessable thru HTTP.
         * @var boolean 
         */
        private $_httponly;

        /**
         * Constructor.
         * 
         * Except for the $key argument, all arguments have the same meaning as 
         * in the documentation of the setcookie() function.
         * 
         * @param string $key The encryption key.
         * @param string $name The name of the cookie. 
         * @param int $expire The number of seconds before the cookie expires. If set to 0, or omitted, the cookie will expire at the end of the session (when the browser closes). 
         * @param string $path The path on the server in which the cookie will be available on.
         * @param string $domain The domain that the cookie is available to. 
         * @param bool $secure Indicates that the cookie should only be transmitted over a secure HTTPS connection from the client.
         * @param bool $httponly When TRUE the cookie will be made accessible only through the HTTP protocol.
         */
        public function __construct($key = null, $name = null, $expire = 0, $path = null, $domain = null, $secure = false, $httponly = false)
        {
                $this->_key = $key;
                $this->_name = $name;
                $this->_expire = $expire;
                $this->_path = $path;
                $this->_domain = $domain;
                $this->_secure = $secure;
                $this->_httponly = $httponly;

                $this->initialize();
        }

        /**
         * Check if user is set.
         * @param string $user The username.
         * @return boolean
         */
        public function exist($user)
        {
                $data = $this->read($user);
                return $data->user == $user;
        }

        /**
         * Create user cookie.
         * @param string $user The username. 
         */
        public function insert($user)
        {
                $data = $this->read($user);
                $data->expires = $this->_expire == 0 ? 0 : time() + $this->_expire;
                $data->addr = $_SERVER['REMOTE_ADDR'];
                $data->user = $user;
                $data->hash = $this->hash($data);
                $this->save($data);
        }

        /**
         * Remove user cookie.
         * @param string $user The username.
         */
        public function remove($user)
        {
                $data = $this->read($user);
                $data->expires = 1;
                $this->save($data);
        }

        /**
         * Save cookie data.
         * @param CookieData $data The cookie data to set.
         * @throws Exception
         */
        private function save($data)
        {
                if (isset($this->_path) && isset($this->_domain)) {
                        $result = setcookie($this->_name, $data->serialize(), $data->expires, $this->_path, $this->_domain, $this->_secure, $this->_httponly);
                } elseif (isset($this->_path)) {
                        $result = setcookie($this->_name, $data->serialize(), $data->expires, $this->_path);
                } else {
                        $result = setcookie($this->_name, $data->serialize(), $data->expires);
                }
                if (!$result) {
                        throw new Exception("Failed set cookie");
                }
        }

        /**
         * Read cookie data.
         * @param string $user The expected username.
         * @return \UUP\Authentication\Storage\CookieData
         */
        private function read($user)
        {
                $data = new CookieData();
                $temp = filter_input(INPUT_COOKIE, $this->_name);

                if (isset($temp)) {
                        $data->unserialize($temp);
                        $this->validate($user, $data);
                }
                return $data;
        }

        /**
         * Read cookie data.
         * @param string $user The expected username.
         * @return CookieData function read($user)
          {
          $data = new CookieData();
          $temp = filter_input(INPUT_COOKIE, $this->name);

          if (isset($temp)) {
          $data->unserialize($temp);
          $this->validate($user, $data);
          }
          return $data;
          }

          /**
         * Compute hash value.
         * @param CookieData $data The cookie data.
         * @return string
         */
        private function hash($data)
        {
                return sha1(sprintf("%s%s%s%d", $this->_key, $data->user, $data->addr, $data->expires));
        }

        /**
         * Validate cookie data.
         * 
         * @param string $user The expected username.
         * @param CookieData $data The cookie data.
         * @throws Exception
         */
        private function validate($user, $data)
        {
                if ($data->hash != $this->hash($data)) {
                        throw new Exception("The cookie hash don't match (" . $data->hash . ")");
                }
                if ($data->addr != $_SERVER['REMOTE_ADDR']) {
                        throw new Exception("The cookie address don't match expected value (" . $data->addr . ").");
                }
                if ($data->user != $user) {
                        throw new Exception("The cookie username don't match expected value (" . $data->user . ").");
                }
                if ($data->expires != 0 && $data->expires < time()) {
                        throw new Exception("The cookie has expired (" . strftime("%x %X", $data->expires) . ")");
                }
        }

        /**
         * Create cookie storage.
         */
        private function initialize()
        {
                if (!isset($this->_key)) {
                        $this->file = sprintf("%s/%s.key", sys_get_temp_dir(), $this->_name);
                        if (file_exists($this->file)) {
                                $this->_key = file_get_contents($this->file);
                        } elseif (function_exists('openssl_random_pseudo_bytes ')) {
                                $this->_key = openssl_random_pseudo_bytes(20, true);
                                file_put_contents($this->file, $this->_key);
                        } elseif (function_exists('crypt')) {
                                $this->_key = crypt(rand(), $_SERVER['REMOTE_ADDR']);
                                file_put_contents($this->file, $this->_key);
                        } else {
                                $this->_key = uniqid(__CLASS__, true);
                                file_put_contents($this->file, $this->_key);
                        }
                }
                if (!isset($this->_name)) {
                        $this->_name = strtr(__CLASS__, '\\', '_');
                }
        }

}
