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

namespace UUP\Authentication;

/**
 * Basic HTTP (WWW-Authenticate) authenticator.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class BasicHttpAuthenticator extends ValidatorAdapter
{

        private $realm;

        /**
         * Constructor.
         * @param CredentialValidator $validator The validator callback object.
         * @param string $realm The authentication realm.
         */
        public function __construct($validator, $realm)
        {
                parent::__construct($validator);
                $this->realm = $realm;
                $this->initialize();
        }

        public function login()
        {
                if (!isset($_SERVER['PHP_AUTH_USER'])) {
                        header(sprintf('WWW-Authenticate: Basic realm="%s"', $this->realm));
                        header('HTTP/1.0 401 Unauthorized');
                        exit;
                } else {
                        $this->validator->login();
                }
        }

        private function initialize()
        {
                if (isset($_SERVER['PHP_AUTH_USER'])) {
                        $this->validator->setCredentials($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']);
                }
        }

}
