<?php

/*
 * Copyright (C) 2014-2016 Anders Lövgren (QNET/BMC CompDept).
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
 * @property-read string $host The server name or IP-address.
 * @property-read int $port The server port.
 * @property-read string $path The server path.
 * 
 * @property CAS_Client $client The CAS client object.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class CasAuthenticator extends AuthenticatorBase implements Restrictor, Authenticator
{

        /**
         * The CAS server host.
         * @var string 
         */
        private $_host;
        /**
         * The CAS server port.
         * @var string 
         */
        private $_port;
        /**
         * The CAS server path.
         * @var string 
         */
        private $_path;
        /**
         * CAS service parameters.
         * @var array 
         */
        private $_params = array();
        /**
         * Current session status.
         * @var int 
         */
        private $_status;

        /**
         * Constructor.
         * @param type $host The CAS server host (required).
         * @param type $port The CAS server port (optional).
         * @param type $path The CAS server path (optional).
         */
        public function __construct($host, $port = 443, $path = "/cas")
        {
                parent::__construct();

                $this->_host = $host;
                $this->_port = $port;
                $this->_path = $path;
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                parent::__destruct();

                $this->_host = null;
                $this->_params = null;
                $this->_path = null;
                $this->_port = null;
                $this->_status = null;

                $this->client = null;
        }

        public function __get($name)
        {
                switch ($name) {
                        case 'client':
                                $this->initialize();
                                return $this->client;
                        case 'host':
                                return $this->_host;
                        case 'port':
                                return $this->_port;
                        case 'path':
                                return $this->_path;
                        default:
                                return parent::__get($name);
                }
        }

        public function __set($name, $value)
        {
                switch ($name) {
                        case 'return':
                                $this->_params['service'] = (string) $value;
                                break;
                        case 'client':
                                $this->client = $value;
                                break;
                        default:
                                parent::__set($name, $value);
                                break;
                }
        }

        /**
         * Check if client is authenticated.
         * @return boolean
         */
        public function accepted()
        {
                $this->invoke();
                $result = $this->client->isAuthenticated();
                $this->leave();
                return $result;
        }

        /**
         * Get logged in username.
         * @return string
         */
        public function getSubject()
        {
                return $this->client->getUser();
        }

        /**
         * Trigger CAS client login.
         */
        public function login()
        {
                $this->client->forceAuthentication();
        }

        /**
         * Trigger CAS client logout.
         */
        public function logout()
        {
                $this->invoke();
                $this->client->logout($this->_params);
                $this->leave();
        }

        /**
         * Initialize CAS client.
         */
        private function initialize()
        {
                $this->requires('jasig/phpcas/CAS.php');
                $this->client = new CAS_Client(CAS_VERSION_2_0, false, $this->_host, $this->_port, $this->_path, false);
                $this->client->setNoCasServerValidation();
        }

        /**
         * Start session before calling any CAS client method.
         */
        private function invoke()
        {
                $this->_status = session_status();

                if (session_status() == PHP_SESSION_NONE &&
                    session_status() != PHP_SESSION_DISABLED) {
                        session_start();
                }
        }

        /**
         * Reset session after calling any CAS client method.
         */
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

        /**
         * Require CAS library.
         * @param string $file The filename.
         */
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
