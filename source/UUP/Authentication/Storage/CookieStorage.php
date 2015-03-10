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
                return base64_encode(serialize((array) $this->data));
        }

        public function unserialize($serialized)
        {
                $this->data = (object) unserialize(base64_decode($serialized));
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

        private $key;
        private $name;
        private $expire;
        private $path;
        private $domain;
        private $secure;
        private $httponly;

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
                $this->key = $key;
                $this->name = $name;
                $this->expire = $expire;
                $this->path = $path;
                $this->domain = $domain;
                $this->secure = $secure;
                $this->httponly = $httponly;

                $this->initialize();
        }

        public function exist($user)
        {
                $data = $this->read($user);
                return $data->user == $user;
        }

        public function insert($user)
        {
                $data = $this->read($user);
                $data->expires = $this->expire == 0 ? 0 : time() + $this->expire;
                $data->addr = $_SERVER['REMOTE_ADDR'];
                $data->user = $user;
                $data->hash = $this->hash($data);
                $this->save($data);
        }

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
                if (isset($this->path) && isset($this->domain)) {
                        $result = setcookie($this->name, $data->serialize(), $data->expires, $this->path, $this->domain, $this->secure, $this->httponly);
                } elseif (isset($this->path)) {
                        $result = setcookie($this->name, $data->serialize(), $data->expires, $this->path);
                } else {
                        $result = setcookie($this->name, $data->serialize(), $data->expires);
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
                $temp = filter_input(INPUT_COOKIE, $this->name);

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
                return sha1(sprintf("%s%s%s%d", $this->key, $data->user, $data->addr, $data->expires));
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

        private function initialize()
        {
                if (!isset($this->key)) {
                        $this->file = sprintf("%s/%s.key", sys_get_temp_dir(), $this->name);
                        if (file_exists($this->file)) {
                                $this->key = file_get_contents($this->file);
                        } elseif (function_exists('openssl_random_pseudo_bytes ')) {
                                $this->key = openssl_random_pseudo_bytes(20, true);
                                file_put_contents($this->file, $this->key);
                        } elseif (function_exists('crypt')) {
                                $this->key = crypt(rand(), $_SERVER['REMOTE_ADDR']);
                                file_put_contents($this->file, $this->key);
                        } else {
                                $this->key = uniqid(__CLASS__, true);
                                file_put_contents($this->file, $this->key);
                        }
                }
                if (!isset($this->name)) {
                        $this->name = strtr(__CLASS__, '\\', '_');
                }
        }

}
