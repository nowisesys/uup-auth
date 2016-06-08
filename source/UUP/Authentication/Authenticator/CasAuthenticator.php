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

use CAS_Client;
use UUP\Authentication\Authenticator\Authenticator;
use UUP\Authentication\Library\Authenticator\AuthenticatorBase;
use UUP\Authentication\Restrictor\Restrictor;

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

        /**
         * @var CAS_Client
         */
        private $_client;
        private $_host;
        private $_port;
        private $_path;
        private $_params = array();
        private $_status;

        public function __construct($host, $port = 443, $path = "/cas")
        {
                $this->_host = $host;
                $this->_port = $port;
                $this->_path = $path;
                $this->initialize();
        }

        public function __set($name, $value)
        {
                if ($name == 'return') {
                        $this->_params['service'] = (string) $value;
                }
        }

        public function accepted()
        {
                $this->invoke();
                $result = $this->_client->isAuthenticated();
                $this->leave();
                return $result;
        }

        public function getSubject()
        {
                return $this->_client->getUser();
        }

        public function login()
        {
                $this->_client->forceAuthentication();
        }

        public function logout()
        {
                $this->invoke();
                $this->_client->logout($this->_params);
                $this->leave();
        }

        private function initialize()
        {
                $this->requires('jasig/phpcas/CAS.php');
                $this->_client = new CAS_Client(CAS_VERSION_2_0, false, $this->_host, $this->_port, $this->_path, false);
                $this->_client->setNoCasServerValidation();
        }

        private function invoke()
        {
                $this->_status = session_status();

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
                if ($this->_status == PHP_SESSION_ACTIVE &&
                    session_status() == PHP_SESSION_NONE) {
                        session_start();
                }
        }

        private function requires($file)
        {
                $locations = array(
                        __DIR__ . '/../../../../../../', // deployed
                        __DIR__ . '/../../../../vendor/'        // package
                );
                foreach ($locations as $location) {
                        if (file_exists($location . $file)) {
                                require_once $location . $file;
                        }
                }
        }

}
