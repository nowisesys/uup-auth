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

namespace UUP\Authentication\Stack;

use UUP\Authentication\Authenticator;

/**
 * Decorator class for concrete authenticator objects. 
 * 
 * This class provides a builder pattern for assigning properties to the 
 * wrapped object:
 * <code>
 * $decorator = new AuthenticatorDecorator($authenticator)
 *      ->name("The name")
 *      ->description("A longer text with more information");
 * </code>
 * 
 * @property-read string $name Short name for wrapped authenticator.
 * @property-read string $description Longer descriptive text for wrapped authenticator.
 * @property-read Authenticator $authenticator The wrapped authenticator object.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class AuthenticatorDecorator implements Authenticator
{

        private $auth;
        private $name;
        private $desc;

        /**
         * Constructor.
         * @param Authenticator $auth The authenticator object.
         * @param string $name Short name for wrapped authenticator.
         * @param string $desc Longer descriptive text for wrapped authenticator.
         */
        public function __construct($auth, $name = "", $desc = "")
        {
                $this->auth = $auth;
        }

        public function __get($name)
        {
                switch ($name) {
                        case 'name':
                                return $this->name;
                        case 'description':
                                return $this->desc;
                        case 'authenticator':
                                return $this->auth;
                }
        }

        /**
         * Sets the short name for wrapped authenticator.
         * @param type $text
         * @return \UUP\Authentication\Stack\AuthenticatorDecorator
         */
        public function name($text)
        {
                $this->name = $text;
                return $this;
        }

        /**
         * Sets a longer descriptive text for wrapped authenticator.
         * @param type $text
         * @return \UUP\Authentication\Stack\AuthenticatorDecorator
         */
        public function description($text)
        {
                $this->desc = $text;
                return $this;
        }

        public function authenticated()
        {
                return $this->auth->authenticated();
        }

        public function getUser()
        {
                return $this->auth->getUser();
        }

        public function login()
        {
                return $this->auth->login();
        }

        public function logout()
        {
                return $this->auth->logout();
        }

}
