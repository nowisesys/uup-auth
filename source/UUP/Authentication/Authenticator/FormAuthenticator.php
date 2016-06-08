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
use UUP\Authentication\Authenticator\RemoteUserAuthenticator;
use UUP\Authentication\Restrictor\Restrictor;
use UUP\Authentication\Storage\SessionStorage;
use UUP\Authentication\Storage\Storage;
use UUP\Authentication\Validator\Validator;

/**
 * HTML form authenticator.
 * 
 * This class authenticates a user based on request parameters. The request 
 * parameters can i.e. be obtained from a submitted form. Notice that this 
 * class is kind of generic, it could also be used to provide authentication
 * for simple GET requests.
 * 
 * These are the default options unless overridden by the options argument
 * for the constructor:
 * 
 * <code>
 * $options = array(
 *      'login'  => '/login',   // Login form URL.
 *      'name'   => 'auth',     // The form name.
 *      'user'   => 'user',     // Request parameter containing the username.
 *      'pass'   => 'pass'      // Request parameter containing the password.
 * );
 * </code>
 * 
 * Lets say that /login/ldap is an URL for obtaining the credentials for 
 * authentication against an LDAP server. Then this class can be used like
 * this:
 * <code>
 * $auth = new FormAuthenticator(
 *      new LdapBindValidator('ldaps://ldap.example.com'),
 *      array('login' => '/login/ldap', 'name' => 'authldap')
 * );
 * </code>
 * 
 * In contrast to the other authenticators the form authenticator don't have 
 * constant access to the username. Its only present when supplied as a POST
 * or GET request parameter, typical when called as part of a REST request or
 * in response to a form submit.
 * 
 * To overcome this limitation, the FormAuthenticator uses a SessionStorage 
 * object to persist the authenticated username between requests. The session
 * storage can be overridden by passing a third argument to the constructor.
 * 
 * @property-read string $name Unique form name, i.e. from hidden field or submit button.
 * @property-read string $user The username request parameter name.
 * @property-read string $pass The password request parameter name.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class FormAuthenticator extends RemoteUserAuthenticator implements Restrictor, Authenticator
{

        private static $_defaults = array(
                'login' => '/login',
                'name'  => 'auth',
                'user'  => 'user',
                'pass'  => 'pass'
        );
        private $_validator;
        private $_session;
        private $_name;
        private $_user;
        private $_pass;
        private $_methods = array(INPUT_POST, INPUT_GET);

        /**
         * Constructor.
         * @param Validator $validator The validator callback object.
         * @param array $options
         * @param Storage $session The session storage.
         */
        public function __construct($validator, $options = array(), $session = null)
        {
                parent::__construct(array_merge(self::$_defaults, $options));

                $this->_validator = $validator;
                $this->_session = $session;
                $this->initialize();

                if (!empty($this->_name) && !empty($this->_user) && !empty($this->_pass)) {
                        $this->authenticate();
                }
        }

        public function __get($name)
        {
                switch ($name) {
                        case 'name':
                                return $this->_options['name'];
                        case 'user':
                                return $this->_options['user'];
                        case 'pass':
                                return $this->_options['pass'];
                        default:
                                return parent::__get($name);
                }
        }

        public function accepted()
        {
                $user = $this->_session->read()->user;
                return $this->_session->exist($user);
        }

        public function getSubject()
        {
                return $this->_session->read()->user;
        }

        public function logout()
        {
                $user = $this->_session->read()->user;
                $this->_session->remove($user);
        }

        /**
         * Set accepted input methods (INPUT_XXX).
         * @param array $methods The accepted input methods, e.g. INPUT_POST.
         */
        public function setMethods($methods)
        {
                $this->_methods = $methods;
        }

        private function authenticate()
        {
                $this->_validator->setCredentials($this->_user, $this->_pass);
                if ($this->_validator->authenticate()) {
                        $this->_session->insert($this->_user);
                }
        }

        private function initialize()
        {
                if (!isset($this->_session)) {
                        $this->_session = new SessionStorage($this->_options['name'], false);
                }
                foreach ($this->_methods as $type) {
                        if (empty($this->_name)) {
                                $this->_name = filter_input($type, $this->_options['name'], FILTER_SANITIZE_STRING);
                        }
                        if (empty($this->_pass)) {
                                $this->_pass = filter_input($type, $this->_options['pass'], FILTER_SANITIZE_STRING);
                        }
                        if (empty($this->_user)) {
                                $this->_user = filter_input($type, $this->_options['user'], FILTER_SANITIZE_STRING);
                        }
                }
        }

}
