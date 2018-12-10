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

namespace UUP\Authentication\Library\Authenticator {

        use UUP\Authentication\Restrictor\Restrictor;
        use UUP\Authentication\Validator\Validator;

        /**
         * Basic HTTP (WWW-Authenticate) access restrictor.
         * 
         * @author Anders Lövgren (Nowise Systems/Uppsala University)
         * @package UUP
         * @subpackage Authentication
         * 
         * @see BasicHttpAuthenticator
         */
        class BasicHttpClient
        {

                /**
                 * @var string The username.
                 */
                private $_user = "";
                /**
                 * @var string The password.
                 */
                private $_pass = "";
                /**
                 * @var Validator 
                 */
                private $_validator;

                /**
                 * Constructor.
                 * @param Validator $validator The validator callback object.
                 */
                public function __construct($validator)
                {
                        $this->_validator = $validator;
                        $this->initialize();
                }

                /**
                 * Destructor.
                 */
                public function __destruct()
                {
                        $this->_user = null;
                        $this->_pass = null;
                        $this->_validator = null;
                }

                /**
                 * Authenticate using current credentials.
                 * @return boolean
                 */
                public function accepted()
                {
                        return $this->_validator->authenticate();
                }

                /**
                 * Get logged on user.
                 * @return string
                 */
                public function getSubject()
                {
                        return $this->_user;
                }

                /**
                 * Initialize this object.
                 */
                private function initialize()
                {
                        if (isset($_SERVER['PHP_AUTH_USER']) && strlen($_SERVER['PHP_AUTH_USER']) != 0) {
                                $this->_user = $_SERVER['PHP_AUTH_USER'];
                        }
                        if (isset($_SERVER['PHP_AUTH_PW']) && strlen($_SERVER['PHP_AUTH_PW']) != 0) {
                                $this->_pass = $_SERVER['PHP_AUTH_PW'];
                        }
                        if (isset($this->_user) && isset($this->_pass)) {
                                $this->_validator->setCredentials($this->_user, $this->_pass);
                        }
                }

                public function setNormalizer(callable $normalizer)
                {
                        // ignore
                }

        }

}

namespace UUP\Authentication\Authenticator {

        use Closure;
        use UUP\Authentication\Authenticator\Authenticator;
        use UUP\Authentication\Library\Authenticator\AuthenticatorBase;
        use UUP\Authentication\Library\Authenticator\BasicHttpClient;
        use UUP\Authentication\Restrictor\Restrictor;
        use UUP\Authentication\Validator\Validator;

        /**
         * Basic HTTP (WWW-Authenticate) authenticator.
         * 
         * @author Anders Lövgren (Nowise Systems/Uppsala University)
         * @package UUP
         * @subpackage Authentication
         */
        class BasicHttpAuthenticator extends AuthenticatorBase implements Restrictor, Authenticator
        {

                use \UUP\Authentication\Library\Authenticator\HttpAuthenticator;

                /**
                 * The client object closure.
                 * @var Closure 
                 */
                private $_closure;
                /**
                 * @var string The authentication realm.
                 */
                private $_realm;

                /**
                 * Constructor.
                 * @param Validator $validator The validator callback object.
                 * @param string $realm The authentication realm.
                 */
                public function __construct($validator, $realm)
                {
                        parent::__construct();
                        $this->_realm = $realm;

                        // 
                        // Use closure to defer initialization until neeeded.
                        // 
                        $this->_closure = function() use ($validator) {
                                return new BasicHttpClient($validator);
                        };
                }

                /**
                 * Destructor.
                 */
                public function __destruct()
                {
                        parent::__destruct();

                        $this->_closure = null;
                        $this->_realm = null;

                        $this->_redirect = null;
                        $this->_message = null;

                        $this->client = null;
                }

                public function __get($name)
                {
                        if ($name == 'client') {
                                $this->initialize();
                                return $this->client;
                        } else {
                                return parent::__get($name);
                        }
                }

                /**
                 * Called when user is unauthorized access.
                 */
                private function unauthorized()
                {
                        header(sprintf('WWW-Authenticate: Basic realm="%s"', $this->_realm));
                        header('HTTP/1.0 401 Unauthorized');
                        if (isset($this->_redirect)) {
                                header(sprintf("Location: %s", $this->_redirect));
                        } else {
                                die($this->_message);
                        }
                }

                /**
                 * Initialize client object.
                 */
                private function initialize()
                {
                        $this->client = call_user_func($this->_closure);
                }

        }

}
