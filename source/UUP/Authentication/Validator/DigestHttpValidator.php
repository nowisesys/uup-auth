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

namespace UUP\Authentication\Validator;

use UUP\Authentication\DigestHttpMessage;

/**
 * Validator for Digest HTTP message.
 *
 * @author Anders Lövgren (Computing Department at BMC, Uppsala University)
 * @package UUP
 * @subpackage Authentication
 */
class DigestHttpValidator extends CredentialValidator
{

        private $message;
        private $realm;

        /**
         * Constructor. 
         * @param string $realm The authentication realm.
         * @param DigestHttpMessage $message The Digest HTTP message to authenticate.
         * @param string $user The expected username.
         * @param string $pass The expected password.
         */
        public function __construct($realm, $message, $user = "", $pass = "")
        {
                parent::__construct($user, $pass);
                $this->realm = $realm;
                $this->message = $message;
        }

        public function authenticate()
        {
                $response = $this->response();
                return $response == $this->message->response;
        }

        /**
         * Set message to authenticate.
         * @param DigestHttpMessage $message The Digest HTTP message to authenticate.
         */
        public function setMessage($message)
        {
                $this->message = $message;
        }

        // 
        // Computer HA1 based on parsed digest values.
        // See http://en.wikipedia.org/wiki/Digest_access_authentication
        // 
        private function ha1()
        {
                if ($this->message->algorithm && $this->message->algorithm == 'MD5-sess') {
                        return md5(sprintf("%s:%s:%s", sprintf("%s:%s:%s", $this->user, $this->realm, $this->pass), $this->message->nonce, $this->message->cnonce));
                } else {
                        return md5(sprintf("%s:%s:%s", $this->user, $this->realm, $this->pass));
                }
        }

        // 
        // Computer HA2 based on parsed digest values.
        // See http://en.wikipedia.org/wiki/Digest_access_authentication
        // 
        private function ha2()
        {
                if ($this->message->qop && $this->message->qop == 'auth-int') {
                        return md5(sprintf("%s:%s:%s", $this->message->method, $this->message->uri, md5($this->message->raw)));
                } else {
                        return md5(sprintf("%s:%s", $this->message->method, $this->message->uri));
                }
        }

        // 
        // Computer response based on parsed digest values.
        // See http://en.wikipedia.org/wiki/Digest_access_authentication
        // 
        private function response()
        {
                if (!$this->message->qop) {
                        return md5(sprintf("%s:%s:%s", $this->ha1(), $this->message->nonce, $this->ha2()));
                } else {
                        return md5(sprintf("%s:%s:%s:%s:%s:%s", $this->ha1(), $this->message->nonce, $this->message->nc, $this->message->cnonce, $this->message->qop, $this->ha2()));
                }
        }

}
