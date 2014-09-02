<?php

/*
 * Copyright (C) 2014 Anders Lövgren (QNET/BMC CompDept).
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

                private $digest;        // raw digest message
                private $data;          // parsed digest message.
                private $method;        // request method
                private $required;

                /**
                 * Constructor.
                 * @param string $message The digest message to parse.
                 * @param array $required Array of required message digest parts.
                 */
                public function __construct($message, $required)
                {
                        $this->digest = $message;
                        $this->required = $required;

                        $this->data = array();
                        $this->method = $_SERVER['REQUEST_METHOD'];

                        $this->parse();
                }

                public function __get($name)
                {
                        switch ($name) {
                                case 'method':
                                        return $this->method;
                                case 'raw':
                                        return $this->digest;
                                default:
                                        if (isset($this->data[$name])) {
                                                return $this->data[$name];
                                        } else {
                                                return false;
                                        }
                        }
                }

                private function parse()
                {
                        if (isset($this->digest)) {
                                $needed = $this->required;
                                $pattern = '@(\w+)=(?:(?:")([^"]+)"|([^\s,$]+))@';
                                $matches = array();

                                preg_match_all($pattern, $this->digest, $matches, PREG_SET_ORDER);

                                foreach ($matches as $m) {
                                        $this->data[$m[1]] = $m[2] ? $m[2] : $m[3];
                                        if (isset($needed[$m[1]])) {
                                                unset($needed[$m[1]]);
                                        }
                                }
                                if (!isset($needed)) {
                                        $this->data = array();
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

                private $provider;

                /**
                 * Constructor
                 * @param PasswordProvider $provider The password provider.
                 */
                public function __construct($provider)
                {
                        $this->provider = $provider;
                }

                /**
                 * Validate the digest message.
                 * @param DigestHttpMessage $message The digest message object.
                 * @return bool True if digest match.
                 */
                public function validate($message, $realm)
                {
                        $user = $message->username;
                        $pass = $this->provider->getPassword($user);
                        $validator = new DigestHttpValidator($realm, $message, $user, $pass);
                        return $validator->authenticate();
                }

        }

}

namespace UUP\Authentication\Authenticator {

        use UUP\Authentication\Library\Authenticator\AuthenticatorBase,
            UUP\Authentication\Validator\PasswordProvider,
            UUP\Authentication\Library\Authenticator\DigestHttpMessage,
            UUP\Authentication\Library\Authenticator\DigestHttpResponse,
            UUP\Authentication\Restrictor\Restrictor;

        /**
         * Digest HTTP (WWW-Authenticate) authenticator.
         *
         * @author Anders Lövgren (Computing Department at BMC, Uppsala University)
         * @package UUP
         * @subpackage Authentication
         */
        class DigestHttpAuthenticator extends AuthenticatorBase implements Restrictor, Authenticator
        {

                use Library\Authenticator\HttpAuthenticator;

                private $nonce;

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
                public function __construct($validator, $realm, $required = array('nonce' => 1, 'nc' => 1, 'cnonce' => 1, 'qop' => 1, 'username' => 1, 'uri' => 1, 'response' => 1, 'algorithm' => 0))
                {
                        $this->config($validator, $realm);
                        $this->initialize($required);
                }

                private function initialize($required)
                {
                        $this->nonce = uniqid();

                        if (isset($_SERVER['PHP_AUTH_DIGEST'])) {               // mod_php
                                $digest = $_SERVER['PHP_AUTH_DIGEST'];
                        } elseif (isset($_SERVER['HTTP_AUTHENTICATION'])) {     // most other servers
                                if (strpos(strtolower($_SERVER['HTTP_AUTHENTICATION']), 'digest') === 0) {
                                        $digest = substr($_SERVER['HTTP_AUTHORIZATION'], 7);
                                }
                        }
                        if (!isset($digest)) {
                                return;         // No digest message to authenticate
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
                        $message = new DigestHttpMessage($digest, $required);
                        $response = new DigestHttpResponse($this->validator);
                        if ($response->validate($message, $this->realm)) {
                                $this->user = $message->username;
                                $this->pass = $this->validator->getPassword($this->user);
                                $this->validator->setCredentials($this->user, $this->pass);
                        }
                }

                private function unauthorized()
                {
                        header(sprintf('WWW-Authenticate: Digest realm="%s",qop="auth",nonce="%s",opaque="%s"', $this->realm, $this->nonce, md5($this->realm)));
                        header('HTTP/1.0 401 Unauthorized');
                        if (isset($this->redirect)) {
                                header(sprintf("Location: %s", $this->redirect));
                        } else {
                                die($this->message);
                        }
                }

        }

}
