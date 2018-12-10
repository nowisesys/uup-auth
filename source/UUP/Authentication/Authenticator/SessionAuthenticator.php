<?php

/*
 * Copyright (C) 2014-2017 Anders Lövgren (Nowise Systems/Uppsala University).
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
 * @author Anders Lövgren (Nowise Systems/Uppsala University)
 * @package UUP
 * @subpackage Authentication
 */
class SessionAuthenticator extends AuthenticatorBase implements Restrictor, Authenticator
{

        /**
         * @var Authenticator|Restrictor 
         */
        private $_authenticator;
        /**
         * @var Storage 
         */
        private $_storage;

        /**
         * Constructor.
         * @param Authenticator $authenticator The authenticator frontend.
         * @param Storage $storage The session storage.
         */
        public function __construct($authenticator, $storage)
        {
                parent::__construct();
                
                $this->_authenticator = $authenticator;
                $this->_storage = $storage;
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                parent::__destruct();
                
                $this->_authenticator = null;
                $this->_storage = null;
        }

        /**
         * Check if session is authenticated.
         * @return boolean
         */
        public function accepted()
        {
                if ($this->_storage->exist($this->_authenticator->getSubject())) {
                        return true;
                } elseif ($this->_authenticator->accepted()) {
                        $this->_storage->insert($this->_authenticator->getSubject());
                        return true;
                } else {
                        return false;
                }
        }

        /**
         * Get authenticated subject.
         * @return string
         */
        public function getSubject()
        {
                return call_user_func($this->_normalizer, $this->_authenticator->getSubject());
        }

        /**
         * Trigger login and insert in storage.
         */
        public function login()
        {
                $this->_authenticator->login();
                $this->_storage->insert($this->_authenticator->getSubject());
        }

        /**
         * Trigger logout and removal from storage.
         */
        public function logout()
        {
                $this->_storage->remove($this->_authenticator->getSubject());
                $this->_authenticator->logout();
        }

}
