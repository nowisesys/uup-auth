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

        private static $defaults = array(
                'login' => '/login',
                'name'  => 'auth',
                'user'  => 'user',
                'pass'  => 'pass'
        );
        private $validator;
        private $session;
        private $name;
        private $user;
        private $pass;
        private $methods = array(INPUT_POST, INPUT_GET);

        /**
         * Constructor.
         * @param Validator $validator The validator callback object.
         * @param array $options
         * @param Storage $session The session storage.
         */
        public function __construct($validator, $options = array(), $session = null)
        {
                parent::__construct(array_merge(self::$defaults, $options));

                $this->validator = $validator;
                $this->session = $session;
                $this->initialize();

                if (!empty($this->name) && !empty($this->user) && !empty($this->pass)) {
                        $this->authenticate();
                }
        }

        public function __get($name)
        {
                switch ($name) {
                        case 'name':
                                return $this->options['name'];
                        case 'user':
                                return $this->options['user'];
                        case 'pass':
                                return $this->options['pass'];
                        default:
                                return parent::__get($name);
                }
        }

        public function accepted()
        {
                $user = $this->session->read()->user;
                return $this->session->exist($user);
        }

        public function getSubject()
        {
                return $this->session->read()->user;
        }

        public function logout()
        {
                $user = $this->session->read()->user;
                $this->session->remove($user);
        }

        /**
         * Set accepted input methods (INPUT_XXX).
         * @param array $methods The accepted input methods, e.g. INPUT_POST.
         */
        public function setMethods($methods)
        {
                $this->methods = $methods;
        }

        private function authenticate()
        {
                $this->validator->setCredentials($this->user, $this->pass);
                if ($this->validator->authenticate()) {
                        $this->session->insert($this->user);
                }
        }

        private function initialize()
        {
                if (!isset($this->session)) {
                        $this->session = new SessionStorage($this->options['name'], false);
                }
                foreach (array('name', 'user', 'pass') as $name) {
                        foreach ($this->methods as $type) {
                                if (empty($this->$name)) {
                                        $this->$name = filter_input($type, $this->options[$name], FILTER_SANITIZE_STRING);
                                }
                        }
                }
        }

}
