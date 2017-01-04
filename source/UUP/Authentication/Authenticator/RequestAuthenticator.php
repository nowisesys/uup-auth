<?php

/*
 * Copyright (C) 2014-2017 Anders Lövgren (QNET/BMC CompDept).
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

namespace UUP\Authentication\Library\Authenticator {

        use UUP\Authentication\Authenticator\RequestAuthenticator;
        use UUP\Authentication\Restrictor\Restrictor;
        use UUP\Authentication\Validator\Validator;

        /**
         * Client for request authenticator.
         * 
         * @author Anders Lövgren (QNET/BMC CompDept)
         * @package UUP
         * @subpackage Authentication
         * 
         * @see RequestAuthenticator
         */
        class RequestClient implements Restrictor
        {

                /**
                 * The request validator.
                 * @var Validator 
                 */
                private $_validator;
                /**
                 * The form name. 
                 * @var string 
                 */
                private $_name;
                /**
                 * The username.
                 * @var string 
                 */
                private $_user;
                /**
                 * The password.
                 * @var string 
                 */
                private $_pass;
                /**
                 * Successful authenticated.
                 * @var boolean 
                 */
                private $_accepted;

                /**
                 * Constructor.
                 * 
                 * @param Validator $validator The validator callback object.
                 * @param array $options Options for request parameters.
                 * @param array $methods The accepted input methods, e.g. INPUT_POST.
                 */
                public function __construct($validator, $options, $methods)
                {
                        $this->_validator = $validator;
                        $this->initialize($options, $methods);
                }

                /**
                 * Destructor.
                 */
                public function __destruct()
                {
                        $this->_accepted = null;
                        $this->_name = null;
                        $this->_pass = null;
                        $this->_user = null;
                        $this->_validator = null;
                }

                /**
                 * Check if user is authenticated.
                 * @return boolean
                 */
                public function accepted()
                {
                        return $this->_accepted;
                }

                /**
                 * Get authenticated user.
                 * @return string
                 */
                public function getSubject()
                {
                        return $this->_user;
                }

                /**
                 * Initialize this object.
                 * @param type $options
                 * @param type $methods
                 */
                private function initialize($options, $methods)
                {
                        foreach ($methods as $type) {
                                if (empty($this->_name)) {
                                        $this->_name = filter_input($type, $options['name'], FILTER_SANITIZE_STRING);
                                }
                                if (empty($this->_user)) {
                                        $this->_user = filter_input($type, $options['user'], FILTER_SANITIZE_STRING);
                                }
                                if (empty($this->_pass)) {
                                        $this->_pass = filter_input($type, $options['pass'], FILTER_SANITIZE_STRING);
                                }
                        }

                        if (!empty($this->_name) && !empty($this->_user) && !empty($this->_pass)) {
                                $this->authenticate();
                        }
                }

                /**
                 * Authenticate request against validator.
                 */
                private function authenticate()
                {
                        $this->_validator->setCredentials($this->_user, $this->_pass);
                        if ($this->_validator->authenticate()) {
                                $this->_accepted = true;
                        }
                }

        }

}

namespace UUP\Authentication\Authenticator {

        use Closure;
        use UUP\Authentication\Authenticator\Authenticator;
        use UUP\Authentication\Authenticator\RemoteUserAuthenticator;
        use UUP\Authentication\Library\Authenticator\RequestClient;
        use UUP\Authentication\Restrictor\Restrictor;
        use UUP\Authentication\Validator\Validator;

        /**
         * HTML POST/GET authenticator.
         * 
         * This class authenticates a user based on POST/GET parameters. The request 
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
         * $auth = new RequestAuthenticator(
         *      new LdapBindValidator('ldaps://ldap.example.com'),
         *      array('login' => '/login/ldap', 'name' => 'authldap')
         * );
         * </code>
         * 
         * This class doesn't support session management by itself. It's meant to be
         * used in conjunction with session management outside of uup-auth:
         * 
         * <code>
         * function handle($auth) 
         * {
         *      if($this->request->logout) {
         *              $this->session->remove($auth->name);
         *      }
         *      if($this->request->login) {
         *              $auth->login(); // redirect
         *      }
         *      if(isset($this->session->has($auth->name)) {
         *              // validate session...
         *      }
         *      if($auth->accepted()) {
         *              $this->session->set($auth->name, $auth->getSubject());
         *      }
         * }
         * </code>
         * 
         * @property-read string $name Unique form name, i.e. from hidden field or submit button.
         * @property-read string $user The username request parameter name.
         * @property-read string $pass The password request parameter name.
         * 
         * @author Anders Lövgren (QNET/BMC CompDept)
         * @package UUP
         * @subpackage Authentication
         */
        class RequestAuthenticator extends RemoteUserAuthenticator implements Restrictor, Authenticator
        {

                /**
                 * Default options.
                 * @var array 
                 */
                private static $_defaults = array(
                        'login' => '/login',
                        'name'  => 'auth',
                        'user'  => 'user',
                        'pass'  => 'pass'
                );
                /**
                 * Accepted request methods.
                 * @var array 
                 */
                private $_methods = array(INPUT_POST, INPUT_GET);
                /**
                 * The client object closure.
                 * @var Closure 
                 */
                private $_closure;

                /**
                 * Constructor.
                 * 
                 * @param Validator $validator The validator callback object.
                 * @param array $options Options for request parameters.
                 */
                public function __construct($validator, $options = array())
                {
                        parent::__construct(array_merge(self::$_defaults, $options));

                        $this->_closure = function($methods) use($validator, $options) {
                                return new RequestClient($validator, $options, $methods);
                        };
                }

                /**
                 * Destructor.
                 */
                public function __destruct()
                {
                        parent::__destruct();

                        $this->_methods = null;
                        $this->_closure = null;
                }

                public function __get($name)
                {
                        switch ($name) {
                                case 'client':
                                        $this->initialize();
                                        return $this->client;
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

                public function __set($name, $value)
                {
                        if ($name == 'client') {
                                $this->client = $value;
                        } else {
                                parent::__set($name, $value);
                        }
                }

                /**
                 * Check if user is authenticated.
                 * @return boolean
                 */
                public function accepted()
                {
                        return $this->client->accepted();
                }

                /**
                 * Get authenticated user.
                 * @return string
                 */
                public function getSubject()
                {
                        return $this->client->getSubject();
                }

                /**
                 * Trigger logout (noop).
                 */
                public function logout()
                {
                        // Ignore
                }

                /**
                 * Set accepted input methods (INPUT_XXX).
                 * @param array $methods The accepted input methods, e.g. INPUT_POST.
                 */
                public function setMethods($methods)
                {
                        $this->_methods = $methods;
                }

                /**
                 * Initialize client object.
                 */
                private function initialize()
                {
                        $this->client = call_user_func($this->_closure, $this->_methods);
                }

        }

}
