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

/**
 * Credential validator callback class. This class is intended to be used 
 * as the base class for backend authenticator interfacing against external 
 * account sources (i.e. PAM, LDAP or SQL).
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
abstract class CredentialValidator
{

        protected $user;
        protected $pass;

        /**
         * Constructor.
         * @param string $user The username to validate.
         * @param string $pass The password to validate.
         */
        public function __construct($user = "", $pass = "")
        {
                $this->user = $user;
                $this->pass = $pass;
        }

        /**
         * Set credentials for authentication.
         * @param string $user The username.
         * @param string $pass The password.
         */
        public function setCredentials($user, $pass)
        {
                $this->user = $user;
                $this->pass = $pass;
        }

        /**
         * Authenticate using currently set credentials. Returns true if authentication succeed.
         * @return bool 
         * @throws Exception
         */
        abstract function authenticate();
}
