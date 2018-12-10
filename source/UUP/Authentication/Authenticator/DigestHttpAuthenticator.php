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
        use UUP\Authentication\Validator\DigestHttpValidator;

        /**
         * Represent an Digest HTTP message.
         * 
         * @property-read string $nonce Message digest part.
         * @property-read string $nc Message digest part.
         * @property-read string $cnonce Message digest part.
         * @property-read string $qop Message digest part.
         * @property-read string $username Message digest part.
         * @property-read string $uri Message digest part.
         * @property-read string $response Message digest part.
         * @property-read string $algorithm Message digest part.
         * @property-read string $method Request method.
         * @property-read string $raw The raw digest message.
         * 
         * @author Anders Lövgren (Computing Department at BMC, Uppsala University)
         * @package UUP
         * @subpackage Authentication
         */
        class DigestHttpMessage
        {

                /**
                 * Raw digest message.
                 * @var string 
                 */
                private $_digest;
                /**
                 * Parsed digest message.
                 * @var string 
                 */
                private $_data;
                /**
                 * Request method.
                 * @var string 
                 */
                private $_method;
                /**
                 * Required message digest parts.
                 * @var array 
                 */
                private $_required;

                /**
                 * Constructor.
                 * @param string $message The digest message to parse.
                 * @param array $required Required message digest parts.
                 */
                public function __construct($message, $required)
                {
                        $this->_digest = $message;
                        $this->_required = $required;

                        $this->_data = array();
                        $this->_method = $_SERVER['REQUEST_METHOD'];

                        $this->parse();
                }

                public function __get($name)
                {
                        switch ($name) {
                                case 'method':
                                        return $this->_method;
                                case 'raw':
                                        return $this->_digest;
                                default:
                                        if (isset($this->_data[$name])) {
                                                return $this->_data[$name];
                                        } else {
                                                return false;
                                        }
                        }
                }

                /**
                 * Parse digest message.
                 */
                private function parse()
                {
                        if (isset($this->_digest)) {
                                $needed = $this->_required;
                                $pattern = '@(\w+)=(?:(?:")([^"]+)"|([^\s,$]+))@';
                                $matches = array();

                                preg_match_all($pattern, $this->_digest, $matches, PREG_SET_ORDER);

                                foreach ($matches as $m) {
                                        $this->_data[$m[1]] = $m[2] ? $m[2] : $m[3];
                                        if (isset($needed[$m[1]])) {
                                                unset($needed[$m[1]]);
                                        }
                                }
                                if (!isset($needed)) {
                                        $this->_data = array();
                                }
                        }
                }

        }

        /**
         * Helper class for validation of Digest HTTP messages.
         * 
         * @author Anders Lövgren (Computing Department at BMC, Uppsala University)
         * @package UUP
         * @subpackage Authentication
         */
        class DigestHttpResponse
        {

                /**
                 * The password provider.
                 * @var PasswordProvider 
                 */
                private $_provider;

                /**
                 * Constructor
                 * @param PasswordProvider $provider The password provider.
                 */
                public function __construct($provider)
                {
                        $this->_provider = $provider;
                }

                /**
                 * Validate the digest message.
                 * @param DigestHttpMessage $message The digest message object.
                 * @return bool True if digest match.
                 */
                public function validate($message, $realm)
                {
                        $user = $message->username;
                        $pass = $this->_provider->getPassword($user);
                        $validator = new DigestHttpValidator($realm, $message, $user, $pass);
                        return $validator->authenticate();
                }

        }

        /**
         * Digest HTTP (WWW-Authenticate) access restrictor.
         * 
         * @author Anders Lövgren (Nowise Systems/Uppsala University)
         * @package UUP
         * @subpackage Authentication
         * 
         * @see DigestHttpAuthenticator
         */
        class DigestHttpClient
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
                 * 
                 * The supplied Validator object must implement the PasswordProvider 
                 * interface to support retrieval of password in clear text in the
                 * server side. This is a inherent requirement due to how the digest
                 * authentication method works.
                 * 
                 * @param Validator $validator The validator callback object.
                 * @param string $realm The authentication realm.
                 * @param array $required Restriction on required digest parts.
                 * 
                 * @see PasswordProvider
                 */
                public function __construct($validator, $realm, $required)
                {
                        $this->_validator = $validator;
                        $this->initialize($realm, $required);
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
                 * 
                 * @param string $realm The authentication realm.
                 * @param array $required Restriction on required digest parts.
                 */
                private function initialize($realm, $required)
                {
                        if (isset($_SERVER['PHP_AUTH_DIGEST'])) {               // mod_php
                                $digest = $_SERVER['PHP_AUTH_DIGEST'];
                        } elseif (isset($_SERVER['HTTP_AUTHENTICATION'])) {     // most other servers
                                if (strpos(strtolower($_SERVER['HTTP_AUTHENTICATION']), 'digest') === 0) {
                                        $digest = substr($_SERVER['HTTP_AUTHORIZATION'], 7);
                                }
                        }

                        if (!isset($digest)) {
                                return;         // No digest message to authenticate
                        } else {
                                $message = new DigestHttpMessage($digest, $required);
                                $response = new DigestHttpResponse($this->_validator);
                        }

                        // 
                        // This is were things start to get messy. The authentication
                        // is done in two distinct steps:
                        // 
                        //   1. Authenticate the digest message itself.
                        //   2. Authenticate the username/password against the validator.
                        // 
                        // The second step is performed when calling the accepted()
                        // method. The account validation is defered until later to make 
                        // this code behave well with session authentication.
                        // 
                        if ($response->validate($message, $realm)) {
                                $this->_user = $message->username;
                                $this->_pass = $this->_validator->getPassword($this->_user);
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
        use UUP\Authentication\Library\Authenticator\DigestHttpClient;
        use UUP\Authentication\Restrictor\Restrictor;
        use UUP\Authentication\Validator\PasswordProvider;
        use UUP\Authentication\Validator\Validator;

        /**
         * Digest HTTP (WWW-Authenticate) authenticator.
         *
         * @author Anders Lövgren (Computing Department at BMC, Uppsala University)
         * @package UUP
         * @subpackage Authentication
         */
        class DigestHttpAuthenticator extends AuthenticatorBase implements Restrictor, Authenticator
        {

                use \UUP\Authentication\Library\Authenticator\HttpAuthenticator;

                /**
                 * The client object closure.
                 * @var Closure 
                 */
                private $_closure;
                /**
                 * Some unique string.
                 * @var string 
                 */
                private $_nonce;
                /**
                 * @var string The authentication realm.
                 */
                private $_realm;

                /**
                 * Constructor.
                 * 
                 * The supplied Validator object must implement the PasswordProvider 
                 * interface to support retrieval of password in clear text in the
                 * server side. This is a inherent requirement due to how the digest
                 * authentication method works.
                 * 
                 * @param Validator $validator The validator callback object.
                 * @param string $realm The authentication realm.
                 * @param array $required Restriction on required digest parts.
                 * @see PasswordProvider
                 */
                public function __construct($validator, $realm, $required = array(
                        'nonce'     => 1,
                        'nc'        => 1,
                        'cnonce'    => 1,
                        'qop'       => 1,
                        'username'  => 1,
                        'uri'       => 1,
                        'response'  => 1,
                        'algorithm' => 0
                ))
                {
                        parent::__construct();

                        $this->_nonce = uniqid();
                        $this->_realm = $realm;

                        $this->_closure = function($realm) use ($validator, $required) {
                                return new DigestHttpClient($validator, $realm, $required);
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
                        $this->_nonce = null;

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
                        header(sprintf('WWW-Authenticate: Digest realm="%s",qop="auth",nonce="%s",opaque="%s"', $this->_realm, $this->_nonce, md5($this->_realm)));
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
                        $this->client = call_user_func($this->_closure, $this->_realm);
                }

        }

}
