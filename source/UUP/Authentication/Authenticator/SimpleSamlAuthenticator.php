<?php

/*
 * Copyright (C) 2016-2017 Anders Lövgren (QNET/BMC CompDept).
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

use SimpleSAML\Auth\Simple as SimpleSAML_Auth_Simple3;
use SimpleSAML_Auth_Simple as SimpleSAML_Auth_Simple1;
use UUP\Authentication\Authenticator\Authenticator;
use UUP\Authentication\Exception;
use UUP\Authentication\Library\Authenticator\AuthenticatorBase;
use UUP\Authentication\Library\Session\SessionAdapter as Session;
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
 * @property SimpleSAML_Auth_Simple $client The simple SAML client object.
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
         * The optional session adapter.
         * @var Session 
         */
        private $_session = false;

        /**
         * Constructor.
         * 
         * @param array $options The config options.
         * @throws Exception
         */
        public function __construct($options = array())
        {
                parent::__construct();

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
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                parent::__destruct();

                $this->_path = null;
                $this->_return = null;
                $this->_spid = null;
                $this->_subject = null;
                $this->_target = null;

                $this->client = null;
        }

        public function __get($name)
        {
                switch ($name) {
                        case 'client':
                                $this->initialize();
                                return $this->client;
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
                        case 'client':
                                $this->client = $value;
                                break;
                        case 'target':
                                $this->_target = (string) $value;
                                break;
                        case 'return':
                                $this->_return = (string) $value;
                                break;
                        case 'subject':
                                $this->_subject = (string) $value;
                                break;
                        default:
                                parent::__set($name, $value);
                                break;
                }
        }

        /**
         * Set session adapter.
         * @param Session $session The session adapter.
         */
        public function setSessionAdapter($session)
        {
                $this->_session = $session;
        }

        /**
         * Check if authenticated.
         * @return boolean
         */
        public function accepted()
        {
                return $this->client->isAuthenticated();
        }

        /**
         * Get username.
         * @return string
         */
        public function getSubject()
        {
                return call_user_func($this->_normalizer, $this->getUser());
        }

        /**
         * Get user attributes.
         * @return array
         */
        public function attributes()
        {
                return $this->client->getAttributes();
        }

        /**
         * Trigger login.
         */
        public function login()
        {
                $this->client->requireAuth(array(
                        'ReturnTo' => $this->_target
                ));
        }

        /**
         * Trigger logout.
         */
        public function logout()
        {
                $this->client->logout(array(
                        'ReturnTo' => $this->_return
                ));
        }

        /**
         * Initialize simple SAML client.
         */
        private function initialize()
        {
                $this->requires('lib/_autoload.php', $this->_path);

                // 
                // Support both new namespaced class and older version:
                // 
                if (class_exists("SimpleSAML\Auth\Simple")) {
                        $this->client = new SimpleSAML_Auth_Simple3($this->_spid);
                } else {
                        $this->client = new SimpleSAML_Auth_Simple1($this->_spid);
                }
        }

        // 
        // Using invoke() and leave() is not really needed if Simple SAML 
        // is setup to use its own session name.
        // 

        /**
         * Called before invoking library methods.
         */
        private function invoke()
        {
                if (!($session = $this->_session)) {
                        return;
                }

                $this->_status = $session->status();

                if ($session->status() == Session::ACTIVE &&
                    $session->status() != Session::DISABLED) {
                        $session->close();
                }
                if ($session->status() == Session::MISSING &&
                    $session->status() != Session::DISABLED) {
                        $session->start();
                }
        }

        /**
         * Called after invoking library methods.
         */
        private function leave()
        {
                if (!($session = $this->_session)) {
                        return;
                }

                if ($session->status() == Session::ACTIVE &&
                    $session->status() != Session::DISABLED) {
                        $session->close();
                }
                if ($this->_status == Session::ACTIVE &&
                    $session->status() == Session::MISSING) {
                        $session->start();
                }
        }

        /**
         * Require simple SAML library.
         * 
         * @param string $file The filename.
         * @param string $path Optional extra directory.
         * @throws Exception
         */
        private function requires($file, $path = null)
        {
                $locations = array(
                        '/usr/share/php/simplesamlphp', // standard
                        __DIR__ . '/../../../../../../simplesamlphp/simplesamlphp', // deployed
                        __DIR__ . '/../../../../vendor/simplesamlphp/simplesamlphp' // package
                );
                if (isset($path)) {
                        if (!in_array($path, $locations)) {
                                array_unshift($locations, $path);
                        }
                }
                foreach ($locations as $location) {
                        if ($this->loaded($location, $file)) {
                                return true;
                        }
                }

                throw new Exception("Failed locate simple SAML installation");
        }

        /**
         * Try require file.
         * @param string $path The directory path.
         * @param string $file The filename.
         * @return boolean
         */
        private function loaded($path, $file)
        {
                $library = realpath(sprintf("%s/%s", $path, $file));

                if (!file_exists($library)) {
                        return false;
                }
                if (!require_once($library)) {
                        return false;
                }

                $this->_path = $path;
                return true;
        }

        /**
         * Get username attribute.
         * @return string
         */
        private function getUser()
        {
                return $this->client->getAttributes()[$this->_subject][0];
        }

}
