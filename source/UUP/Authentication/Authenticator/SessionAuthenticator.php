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

namespace UUP\Authentication\Authenticator;

use UUP\Authentication\Authenticator\Authenticator;
use UUP\Authentication\Library\Authenticator\AuthenticatorBase;
use UUP\Authentication\Restrictor\Restrictor;
use UUP\Authentication\Storage\Storage;

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
class SessionAuthenticator extends AuthenticatorBase implements Restrictor, Authenticator
{

        /**
         * @var Authenticator|Restrictor 
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

        public function accepted()
        {
                if ($this->storage->exist($this->authenticator->getSubject())) {
                        return true;
                } elseif ($this->authenticator->accepted()) {
                        $this->storage->insert($this->authenticator->getSubject());
                        return true;
                } else {
                        return false;
                }
        }

        public function getSubject()
        {
                return $this->authenticator->getSubject();
        }

        public function login()
        {
                $this->authenticator->login();
                $this->storage->insert($this->authenticator->getSubject());
        }

        public function logout()
        {
                $this->storage->remove($this->authenticator->getSubject());
                $this->authenticator->logout();
        }

}
