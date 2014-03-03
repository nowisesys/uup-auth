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
use UUP\Authentication\Exception;

/**
 * Plugin class for unauthenticated session.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class NullAuthenticator implements Authenticator
{

        public function authenticated()
        {
                return false;
        }

        public function getUser()
        {
                return "";
        }

        public function login()
        {
                // ignore
        }

        public function logout()
        {
                // ignore
        }

}

/**
 * The stack of authenticator objects. This class can be used to support
 * multiple authentication methods in a uniform way.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class AuthenticatorStack implements Authenticator
{

        /**
         * @var array 
         */
        private $authenticators;
        /**
         * @var Authenticator Current accepted authenticator.
         */
        private $authenticator;

        /**
         * Constructor.
         * @param Authenticator[] $authenticators
         */
        public function __construct($authenticators = array())
        {
                $this->authenticators = $authenticators;
                $this->authenticator = new NullAuthenticator();
        }

        /**
         * Adds an authenticator to the stack.
         * @param Authenticator $authenticator
         */
        public function add($authenticator)
        {
                $this->authenticators[] = $authenticator;
        }

        /**
         * Get current accepted authenticator.
         * @return Authenticator
         */
        public function getAuthenticator()
        {
                return $this->authenticator;
        }

        /**
         * Set the accepted authenticator that is going to be used for next
         * call to login() or logout(). It can also be the authenticator 
         * already used for an accepted login event.
         * 
         * @param Authenticator $authenticator
         */
        public function setAuthenticator($authenticator)
        {
                $this->authenticator = $authenticator;
        }

        /**
         * Check if any authenticator in the stack accepts the caller as 
         * a logged in user. 
         * @return bool
         */
        public function authenticated()
        {
                if (!$this->authenticator->authenticated()) {
                        foreach ($this->authenticators as $authenticator) {
                                if ($authenticator->authenticated()) {
                                        $this->authenticator = $authenticator;
                                }
                        }
                }
                return $this->authenticator->authenticated();
        }

        /**
         * Get username from current accepted authenticator.
         * @return string 
         */
        public function getUser()
        {
                return $this->authenticator->getUser();
        }

        public function login()
        {
                $this->authenticator->login();
        }

        public function logout()
        {
                $this->authenticator->logout();
        }

}
