<?php

/*
 * Copyright (C) 2016 Anders Lövgren (QNET/BMC CompDept).
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

use SimpleSAML_Auth_Simple;
use UUP\Authentication\Authenticator\Authenticator;
use UUP\Authentication\Exception;
use UUP\Authentication\Library\Authenticator\AuthenticatorBase;
use UUP\Authentication\Restrictor\Restrictor;

/**
 * Simple SAML (i.e. SWAMID) authenticator.
 * 
 * Enterprise authentication using Simple SAML. The installation is searched for 
 * in a couple of standard locations. If installed somewhere else, supply the path 
 * during construction:
 * 
 * <code>
 * $authenticator = new SimpleSamlAuthenticator(array(
 *         'path' => '/opt/simplesaml'
 * ));
 * 
 * if (!$authenticator->accepted()) {
 *         $authenticator->login();
 * } else {
 *         printf("Welcome %s\n", $authenticator->getSubject());
 * }
 * </code>
 * 
 * The constructor options and their default values are:
 * 
 * <code>
 * $options = array(
 *              'spid'   => 'default-sp',     // The service provider identifier
 *              'path'   => null,             // Only check standard locations
 *              'target' => '/auth/login',    // The redirect URL on login
 *              'return' => '/auth/logout'    // The redirect URL on logout
 * );
 * </code>
 * 
 * @property-write string $subject The subject attribute name.
 * 
 * @property string $target The redirect URL on login.
 * @property string $return The redirect URL on logout.
 * 
 * @property-read string $path The installation path.
 * @property-read string $spid The service provider identifier.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class SimpleSamlAuthenticator extends AuthenticatorBase implements Restrictor, Authenticator
{

        /**
         * The user principal attribute name.
         */
        const PRINCIPAL = 'eduPersonPrincipalName';
        /**
         * The default session name (see simplesamlphp config).
         */
        const SESSION_NAME = 'simplesaml';

        /**
         * The simple SAML object.
         * @var SimpleSAML_Auth_Simple 
         */
        private $_client;
        /**
         * Target base URI.
         * @var string 
         */
        private $_target;
        /**
         * The login/logout URL.
         * @var string 
         */
        private $_return;
        /**
         * The subject attribute name.
         * @var string
         */
        private $_subject;
        /**
         * The service provider identifier.
         * @var string
         */
        private $_spid;
        /**
         * The installation path.
         * @var string
         */
        private $_path;

        /**
         * Constructor.
         * 
         * @param array $options The config options.
         * @throws Exception
         */
        public function __construct($options = array())
        {
                if (!isset($options['target'])) {
                        $this->_target = '/auth/login';
                } else {
                        $this->_target = $options['target'];
                }

                if (!isset($options['return'])) {
                        $this->_return = '/auth/logout';
                } else {
                        $this->_return = $options['return'];
                }

                if (!isset($options['spid'])) {
                        $this->_spid = 'default-sp';
                } else {
                        $this->_spid = $options['spid'];
                }

                if (!isset($options['path'])) {
                        $this->_path = null;
                } else {
                        $this->_path = $options['path'];
                }

                if (!isset($options['subject'])) {
                        $this->_subject = self::PRINCIPAL;
                } else {
                        $this->_subject = $options['subject'];
                }

                if (!$this->requires('lib/_autoload.php', $this->_path)) {
                        throw new Exception("Failed locate any Simple SAML installation");
                }

                $this->_client = new SimpleSAML_Auth_Simple($this->_spid);
        }

        public function __get($name)
        {
                switch ($name) {
                        case 'target':
                                return $this->_target;
                        case 'return':
                                return $this->_return;
                        case 'path':
                                return $this->_path;
                        case 'spid':
                                return $this->_spid;
                        default:
                                return parent::__get($name);
                }
        }

        public function __set($name, $value)
        {
                switch ($name) {
                        case 'target':
                                $this->_target = (string) $value;
                                break;
                        case 'return':
                                $this->_return = (string) $value;
                                break;
                        case 'subject':
                                $this->_subject = (string) $value;
                                break;
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
                $this->invoke();
                $result = $this->_client->getAttributes()[$this->_subject][0];
                $this->leave();
                return $result;
        }

        public function attributes()
        {
                $this->invoke();
                $result = $this->_client->getAttributes();
                $this->leave();
                return $result;
        }

        public function login()
        {
                $this->invoke();
                $this->_client->requireAuth(array(
                        'ReturnTo' => $this->_target
                ));
                $this->leave();
        }

        public function logout()
        {
                $this->invoke();
                $this->_client->logout(array(
                        'ReturnTo' => $this->_return
                ));
                $this->leave();
        }

        private function invoke()
        {
                $this->_status = session_status();

                if (session_status() == PHP_SESSION_ACTIVE &&
                    session_status() != PHP_SESSION_DISABLED) {
                        session_write_close();
                }
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

        private function requires($file, $path = null)
        {
                $locations = array(
                        '/usr/share/php/simplesamlphp/', // standard
                        __DIR__ . '/../../../../../../', // deployed
                        __DIR__ . '/../../../../vendor/' // package
                );
                if (isset($path)) {
                        if (!in_array($path, $locations)) {
                                array_unshift($locations, $path);
                        }
                }
                foreach ($locations as $location) {
                        if (file_exists($location . $file)) {
                                require_once $location . $file;
                                $this->_path = $location;
                                return true;
                        }
                }
        }

}
