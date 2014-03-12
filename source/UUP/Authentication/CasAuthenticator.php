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

use UUP\Authentication\Library\Authenticator\AuthenticatorBase;

require_once 'CAS.php';

/**
 * Authenticator for CAS.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class CasAuthenticator extends AuthenticatorBase
{

        private $host;
        private $port;
        private $path;
        private $client;

        public function __construct($host, $port = 443, $path = "/cas")
        {
                $this->host = $host;
                $this->port = $port;
                $this->path = $path;
                $this->initialize();
        }

        public function authenticated()
        {
                return $this->client->isAuthenticated();
        }

        public function getUser()
        {
                return $this->client->getUser();
        }

        public function login()
        {
                $this->client->forceAuthentication();
        }

        public function logout()
        {
                $this->client->logout();
        }

        private function initialize()
        {
                $this->client = new \CAS_Client(CAS_VERSION_2_0, false, $this->host, $this->port, $this->path);
                $this->client->setNoCasServerValidation();
        }

}
