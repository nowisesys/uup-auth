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

namespace UUP\Authentication\Validator;

use UUP\Authentication\Library\Authenticator\DigestHttpMessage;
use UUP\Authentication\Validator\CredentialValidator;

/**
 * Validator for Digest HTTP message.
 *
 * @author Anders Lövgren (Computing Department at BMC, Uppsala University)
 * @package UUP
 * @subpackage Authentication
 */
class DigestHttpValidator extends CredentialValidator
{

        /**
         * The HTTP digest message to authenticate.
         * @var DigestHttpMessage 
         */
        private $_message;
        /**
         * The authentication realm.
         * @var string 
         */
        private $_realm;

        /**
         * Constructor. 
         * @param string $realm The authentication realm.
         * @param DigestHttpMessage $message The HTTP digest message to authenticate.
         * @param string $user The expected username.
         * @param string $pass The expected password.
         */
        public function __construct($realm, $message, $user = "", $pass = "")
        {
                parent::__construct($user, $pass);
                $this->_realm = $realm;
                $this->_message = $message;
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                parent::__destruct();
                $this->_message = null;
                $this->_realm = null;
        }

        /**
         * Authenticate using currently set credentials. Returns true if authentication succeed.
         * @return bool 
         * @throws Exception
         */
        public function authenticate()
        {
                $response1 = $this->response();
                $response2 = $this->_message->response;
                
                return $response1 == $response2;
        }

        /**
         * Set message to authenticate.
         * @param DigestHttpMessage $message The Digest HTTP message to authenticate.
         */
        public function setMessage($message)
        {
                $this->_message = $message;
        }

        /**
         * Compute HA1 based on parsed digest values.
         * @return string
         * @link http://en.wikipedia.org/wiki/Digest_access_authentication
         */
        private function ha1()
        {
                if ($this->_message->algorithm && $this->_message->algorithm == 'MD5-sess') {
                        return md5(sprintf("%s:%s:%s", sprintf("%s:%s:%s", $this->_user, $this->_realm, $this->_pass), $this->_message->nonce, $this->_message->cnonce));
                } else {
                        return md5(sprintf("%s:%s:%s", $this->_user, $this->_realm, $this->_pass));
                }
        }

        /**
         * Compute HA2 based on parsed digest values.
         * @return string
         * @link http://en.wikipedia.org/wiki/Digest_access_authentication
         */
        private function ha2()
        {
                if ($this->_message->qop && $this->_message->qop == 'auth-int') {
                        return md5(sprintf("%s:%s:%s", $this->_message->method, $this->_message->uri, md5($this->_message->raw)));
                } else {
                        return md5(sprintf("%s:%s", $this->_message->method, $this->_message->uri));
                }
        }

        /**
         * Compute response based on parsed digest values.
         * @return string
         * @link http://en.wikipedia.org/wiki/Digest_access_authentication
         */
        private function response()
        {
                if (!$this->_message->qop) {
                        return md5(sprintf("%s:%s:%s", $this->ha1(), $this->_message->nonce, $this->ha2()));
                } else {
                        return md5(sprintf("%s:%s:%s:%s:%s:%s", $this->ha1(), $this->_message->nonce, $this->_message->nc, $this->_message->cnonce, $this->_message->qop, $this->ha2()));
                }
        }

}
