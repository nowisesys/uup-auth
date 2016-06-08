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
use UUP\Authentication\Library\Authenticator\AuthenticatorBase;
use UUP\Authentication\Restrictor\Restrictor;
use UUP\Authentication\Validator\Validator;

/**
 * Basic HTTP (WWW-Authenticate) authenticator.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class BasicHttpAuthenticator extends AuthenticatorBase implements Restrictor, Authenticator
{

        use \UUP\Authentication\Library\Authenticator\HttpAuthenticator;

        /**
         * Constructor.
         * @param Validator $validator The validator callback object.
         * @param string $realm The authentication realm.
         */
        public function __construct($validator, $realm)
        {
                $this->config($validator, $realm);
                $this->initialize();
        }

        private function initialize()
        {
                if (isset($_SERVER['PHP_AUTH_USER']) && strlen($_SERVER['PHP_AUTH_USER']) != 0) {
                        $this->_user = $_SERVER['PHP_AUTH_USER'];
                }
                if (isset($_SERVER['PHP_AUTH_PW']) && strlen($_SERVER['PHP_AUTH_PW']) != 0) {
                        $this->_pass = $_SERVER['PHP_AUTH_PW'];
                }
                $this->_validator->setCredentials($this->_user, $this->_pass);
        }

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

}
