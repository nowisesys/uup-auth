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

use UUP\Authentication\Library\Authenticator\AuthenticatorBase,
    UUP\Authentication\Storage\Storage;

/**
 * Session authenticator.
 * 
 * Provides a session authenticator. This class can wrap any authenticator object
 * to provide session management for the wrapped authenticator. 
 * 
 * Notice that the session management is not limited to ordinary PHP sessions. Any
 * of the storage classes can be used, including user defined classes.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class SessionAuthenticator extends AuthenticatorBase
{

        /**
         * @var Authenticator 
         */
        private $authenticator;
        /**
         * @var Storage 
         */
        private $storage;

        /**
         * Constructor.
         * @param Authenticator $authenticator The authenticator frontend.
         * @param Storage $storage The session storage.
         */
        public function __construct($authenticator, $storage)
        {
                $this->authenticator = $authenticator;
                $this->storage = $storage;
        }

        public function authenticated()
        {
                if ($this->storage->exist($this->authenticator->getUser())) {
                        return true;
                } elseif ($this->authenticator->authenticated()) {
                        $this->storage->insert($this->authenticator->getUser());
                        return true;
                } else {
                        return false;
                }
        }

        public function getUser()
        {
                return $this->authenticator->getUser();
        }

        public function login()
        {
                $this->authenticator->login();
                $this->storage->insert($this->authenticator->getUser());
        }

        public function logout()
        {
                $this->storage->remove($this->authenticator->getUser());
                $this->authenticator->logout();
        }

}