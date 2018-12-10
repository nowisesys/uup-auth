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

/**
 * Remote user environment variable authenticator.
 * 
 * This is a generic authenticator for enterprise level authentication that 
 * is handled outside of PHP by a Apache module or a frontend web proxy. 
 * 
 * Typical examples of such authentication are Kerberos and SAML2 authentication. 
 * The authentication subject (the username) is made available for authorization 
 * in the $_SERVER['REMOTE_USER']. 
 * 
 * This code excerpt show how to setup a remote user authenticator to handle 
 * login/logout using Kerberos 5. This class must be supported by web server 
 * configuration (see config/kerberos_auth.conf) and some PHP code that is
 * runned as handlers for the login/logout locations passed to the constructor.
 * 
 * The return URL from the login/logout handlers can be configured thru the 
 * redirect property. Unless defined, the redirect is done to the URL that
 * triggered the login/logout.
 * 
 * <code>
 * $authenticator = new RemoteUserAuthenticator(
 *      array(
 *              'login'  => '/login/krb5', 
 *              'logout' => '/logout/krb5',
 *      );
 * );
 * </code>
 * 
 * @property string $return The redirect URL on login/logout.
 * @property-write string $subject Override the subject (authenticated user) mapping.
 * 
 * @author Anders Lövgren (Computing Department at BMC, Uppsala University)
 */
class RemoteUserAuthenticator extends AuthenticatorBase implements Restrictor, Authenticator
{

        /**
         * Default login location.
         */
        const LOGIN = 'login';
        /**
         * Default logout location.
         */
        const LOGOUT = 'logout';

        /**
         * Custom options.
         * @var array 
         */
        protected $_options;
        /**
         * The server variable name containing logged on user.
         * @var string 
         */
        private $_subject = 'REMOTE_USER';
        /**
         * The login/logout handler location.
         * @var string 
         */
        private $_handler;
        /**
         * The return URL.
         * @var string 
         */
        private $_return;

        /**
         * Constructor.
         * @param array $options Custom options.
         */
        public function __construct($options)
        {
                parent::__construct();

                $this->_options = $options;

                if (isset($options['return'])) {
                        $this->_return = $options['return'];
                }
                if (!isset($this->_return)) {
                        $this->_return = filter_input(INPUT_SERVER, 'HTTP_REFERER');
                }
                if (!isset($this->_return)) {
                        $this->_return = filter_input(INPUT_SERVER, 'REQUEST_URI');
                }
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                parent::__destruct();

                $this->_options = null;
                $this->_subject = null;
                $this->_handler = null;
                $this->_return = null;
        }

        public function __get($name)
        {
                if ($name == 'return') {
                        return $this->_return;
                } else {
                        return parent::__get($name);
                }
        }

        public function __set($name, $value)
        {
                if ($name == 'return') {
                        $this->_return = (string) $value;
                }
                if ($name == 'subject') {
                        $this->_subject = (string) $value;
                }
        }

        /**
         * Check if remote user is set.
         * @return boolean
         */
        public function accepted()
        {
                return isset($_SERVER[$this->_subject]);
        }

        /**
         * Get remote user subject.
         * @return string
         */
        public function getSubject()
        {
                return call_user_func($this->_normalizer, $_SERVER[$this->_subject]);
        }

        /**
         * Trigger remote user login.
         */
        public function login()
        {
                $this->redirect(self::LOGIN);
        }

        /**
         * Trigger remote user logout.
         */
        public function logout()
        {
                $this->redirect(self::LOGOUT);
        }

        /**
         * Redirect client to login/logout URL.
         * @param string $method The requested method.
         */
        private function redirect($method)
        {
                if (!isset($this->_handler)) {
                        $this->_handler = $this->_options[$method];
                }
                if (!isset($this->_return)) {
                        $this->_return = filter_input(INPUT_SERVER, 'HTTP_REFERER');
                }
                if (!isset($this->_return)) {
                        $this->_return = filter_input(INPUT_SERVER, 'REQUEST_URI');
                }

                header(sprintf("Location: %s", self::destination($this->_handler, $this->_return)));
        }

        /**
         * Generate redirect URL.
         * @param string $handler The login/logout location.
         * @param string $return The return URL.
         * @return string
         */
        private static function destination($handler, $return)
        {
                if (!$return) {
                        return $handler;
                } elseif (strstr($handler, '?')) {
                        return sprintf("%s&return=%s", $handler, urlencode($return));
                } else {
                        return sprintf("%s?return=%s", $handler, urlencode($return));
                }
        }

}
