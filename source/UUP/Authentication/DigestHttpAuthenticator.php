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

namespace UUP\Authentication;

use UUP\Authentication\Validator\DigestHttpValidator;
use UUP\Authentication\Validator\PasswordProvider;

/**
 * Represent an Digest HTTP message.
 * 
 * @property-read string $nonce Message digest part.
 * @property-read string $nc Message digest part.
 * @property-read string $cnonce Message digest part.
 * @property-read string $qop Message digest part.
 * @property-read string $username Message digest part.
 * @property-read string $uri Message digest part.
 * @property-read string $response Message digest part.
 * @property-read string $algorithm Message digest part.
 * @property-read string $method Request method.
 * @property-read string $raw The raw digest message.
 */
class DigestHttpMessage
{

        private $digest;        // raw digest message
        private $data;          // parsed digest message.
        private $method;        // request method
        private $required;

        /**
         * Constructor.
         * @param string $message The digest message to parse.
         * @param array $required Array of required message digest parts.
         */
        public function __construct($message, $required)
        {
                $this->digest = $message;
                $this->required = $required;

                $this->data = array();
                $this->method = $_SERVER['REQUEST_METHOD'];

                $this->parse();
        }

        public function __get($name)
        {
                switch ($name) {
                        case 'method':
                                return $this->method;
                        case 'raw':
                                return $this->digest;
                        default:
                                if (isset($this->data[$name])) {
                                        return $this->data[$name];
                                } else {
                                        return false;
                                }
                }
        }

        private function parse()
        {
                if (isset($this->digest)) {
                        $needed = $this->required;
                        $pattern = '@(\w+)=(?:(?:")([^"]+)"|([^\s,$]+))@';
                        $matches = array();

                        preg_match_all($pattern, $this->digest, $matches, PREG_SET_ORDER);

                        foreach ($matches as $m) {
                                $this->data[$m[1]] = $m[2] ? $m[2] : $m[3];
                                if (isset($needed[$m[1]])) {
                                        unset($needed[$m[1]]);
                                }
                        }
                        if (!isset($needed)) {
                                $this->data = array();
                        }
                }
        }

}

/**
 * Helper class for validation of Digest HTTP messages.
 */
class DigestHttpResponse
{

        private $provider;

        /**
         * Constructor
         * @param PasswordProvider $provider The password provider.
         */
        public function __construct($provider)
        {
                $this->provider = $provider;
        }

        /**
         * Validate the digest message.
         * @param DigestHttpMessage $message The digest message object.
         * @return bool True if digest match.
         */
        public function validate($message, $realm)
        {
                $user = $message->username;
                $pass = $this->provider->getPassword($user);
                $validator = new DigestHttpValidator($realm, $message, $user, $pass);
                return $validator->authenticate();
        }

}

/**
 * Digest HTTP (WWW-Authenticate) authenticator.
 *
 * @author Anders Lövgren (Computing Department at BMC, Uppsala University)
 * @package UUP
 * @subpackage Authentication
 */
class DigestHttpAuthenticator extends HttpAuthenticator implements Authenticator
{

        private $user = "";
        private $nonce;

        /**
         * Constructor. The supplied Validator object must implement the PasswordProvider
         * interface.
         * @param Validator $validator The validator callback object.
         * @param Storage $storage The storage backend object.
         * @param string $realm The authentication realm.
         * @param array $required Restriction on required digest parts.
         */
        public function __construct($validator, $storage, $realm, $required = array('nonce' => 1, 'nc' => 1, 'cnonce' => 1, 'qop' => 1, 'username' => 1, 'uri' => 1, 'response' => 1, 'algorithm' => 0))
        {
                parent::__construct($validator, $storage, $realm);
                $this->initialize($required);
        }

        public function authenticated()
        {
                return $this->storage->exist($this->user);
        }

        public function getUser()
        {
                return $this->user;
        }

        public function login()
        {
                if (strlen($this->user) == 0) {
                        $this->unauthorized();
                } elseif (!$this->validator->authenticate()) {
                        $this->unauthorized();
                } else {
                        $this->storage->insert($this->user);
                }
        }

        public function logout()
        {
                $this->storage->remove($this->user);
                $this->unauthorized();
        }

        private function initialize($required)
        {
                $this->nonce = uniqid();
                
                if (isset($_SERVER['PHP_AUTH_DIGEST'])) {               // mod_php
                        $digest = $_SERVER['PHP_AUTH_DIGEST'];
                } elseif (isset($_SERVER['HTTP_AUTHENTICATION'])) {     // most other servers
                        if (strpos(strtolower($_SERVER['HTTP_AUTHENTICATION']), 'digest') === 0) {
                                $digest = substr($_SERVER['HTTP_AUTHORIZATION'], 7);
                        }
                }
                if (isset($digest)) {
                        // 
                        // Kind of messy. Authentication is done in two steps:
                        // 
                        // 1. Authenticate the digest message.
                        // 2. Authenticate the user/pass against the selected validator.
                        // 
                        $message = new DigestHttpMessage($digest, $required);
                        $response = new DigestHttpResponse($this->validator);
                        if ($response->validate($message, $this->realm)) {
                                $user = $message->username;
                                $pass = $this->validator->getPassword($user);
                                $this->validator->setCredentials($user, $pass);
                                $this->user = $message->username;
                        }
                }
        }

        private function unauthorized()
        {
                header(sprintf('WWW-Authenticate: Digest realm="%s",qop="auth",nonce="%s",opaque="%s"', $this->realm, $this->nonce, md5($this->realm)));
                header('HTTP/1.0 401 Unauthorized');
                if (isset($this->redirect)) {
                        header(sprintf("Location: %s", $this->redirect));
                } else {
                        die($this->message);
                }
        }

}
