<?php

/*
 * Copyright (C) 2014-2017 Anders Lövgren (QNET/BMC CompDept).
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

namespace UUP\Authentication\Library\Authenticator;

/**
 * Trait for HTTP authenticators. 
 * 
 * Provides uniform login/logout functionality for all HTTP authenticator 
 * classes using this trait. Defines the methods that implements the Authenticator 
 * interface.
 * 
 * The redirect property affects whether the browser is instructed to clear 
 * the username and password associated with the authentication realm.
 * 
 * The user class should define the client object used to perform the real validation
 * and authorization. It should also define the member method unauthorized() that
 * gets called on authorization failure.
 * 
 * @property-write string $redirect The redirect URL.
 * @property-write string $message Text to send if user hits Cancel button.
 * 
 * @author Anders Lövgren (Computing Department at BMC, Uppsala University)
 * @package UUP
 * @subpackage Authentication
 */
trait HttpAuthenticator
{

        /**
         * @var string The redirect URL. 
         */
        private $_redirect = null;
        /**
         * @var string 
         */
        private $_message = "";

        public function __set($name, $value)
        {
                switch ($name) {
                        case "redirect":
                                $this->_redirect = (string) $value;
                                break;
                        case "message":
                                $this->_message = (string) $value;
                                break;
                        case "client":
                                $this->client = $value;
                                break;
                }
        }

        /**
         * Check if accepted by validator.
         * @return boolean
         */
        public function accepted()
        {
                return $this->client->accepted();
        }

        /**
         * Get authenticated subject (e.g. username).
         * @return string
         */
        public function getSubject()
        {
                return call_user_func($this->_normalizer, $this->client->getSubject());
        }

        /**
         * Trigger login.
         */
        public function login()
        {
                try {
                        if (strlen($this->client->getSubject()) == 0) {
                                $this->unauthorized();
                        } elseif (!$this->client->accepted()) {
                                $this->unauthorized();
                        }
                } catch (Exception $exception) {
                        error_log($exception->getMessage());
                        $this->unauthorized();
                }
        }

        /**
         * Trigger logout.
         */
        public function logout()
        {
                $this->unauthorized();
        }

}
