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

require_once 'CAS.php';

/**
 * Authenticator for CAS.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class CasAuthenticator implements Authenticator
{

        private $host;
        private $port;
        private $path;

        public function __construct($host, $port = 443, $path = "/cas")
        {
                $this->host = $host;
                $this->port = $port;
                $this->path = $path;
                $this->initialize();
        }

        public function authenticated()
        {
                return strlen(phpCAS::getUser() != 0);
        }

        public function getUser()
        {
                return phpCAS::getUser();
        }

        public function login()
        {
                phpCAS::forceAuthentication();
        }

        public function logout()
        {
                phpCAS::logout();
        }

        private function initialize()
        {
                phpCAS::client(CAS_VERSION_2_0, $this->host, $this->port, $this->path);
                phpCAS::setNoCasServerValidation();
        }

}
