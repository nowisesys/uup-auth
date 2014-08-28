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
 * CAS (Central Authentication Service) authenticator.
 * 
 * <b>Warning:</b> This class should be used after any other authenticator that 
 * uses session data because it tries to decode session data it has not created
 * by itself.
 * 
 * @property-write string $return The redirect URL on logout.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class CasAuthenticator extends AuthenticatorBase implements Restrictor, Authenticator
{

        private $host;
        private $port;
        private $path;
        private $client;
        private $params = array();

        public function __construct($host, $port = 443, $path = "/cas")
        {
                $this->host = $host;
                $this->port = $port;
                $this->path = $path;
                $this->initialize();
        }

        public function __set($name, $value)
        {
                if ($name == 'return') {
                        $this->params['service'] = (string) $value;
                }
        }

        public function accepted()
        {
                $this->invoke();
                $result = $this->client->isAuthenticated();
                $this->leave();
                return $result;
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
                $this->invoke();
                $this->client->logout($this->params);
                $this->leave();
        }

        private function initialize()
        {
                $this->client = new \CAS_Client(CAS_VERSION_2_0, false, $this->host, $this->port, $this->path);
                $this->client->setNoCasServerValidation();
        }

        private function invoke()
        {
                if (session_status() == PHP_SESSION_NONE &&
                    session_status() != PHP_SESSION_DISABLED) {
                        session_start();
                }
        }

        private function leave()
        {
                if (session_status() == PHP_SESSION_ACTIVE &&
                    session_status() != PHP_SESSION_DISABLED) {
                        session_write_close();
                }
        }

}
