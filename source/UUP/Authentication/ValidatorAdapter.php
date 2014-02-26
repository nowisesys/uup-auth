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

use UUP\Authentication\Validator\CredentialValidator;

/**
 * Adapter class between the authenticator frontend and the validator backend.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class ValidatorAdapter implements Authenticator
{

        /**
         * @var CredentialValidator 
         */
        protected $validator;

        /**
         * Constructor.
         * @param CredentialValidator $validator The credentials validator backend.
         */
        public function __construct($validator)
        {
                $this->validator = $validator;
        }

        public function authenticated()
        {
                return $this->validator->authenticated();
        }

        public function getUser()
        {
                return $this->validator->getUser();
        }

        public function login()
        {
                $this->validator->login();
        }

        public function logout()
        {
                $this->validator->logout();
        }

}
