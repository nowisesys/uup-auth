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
class BasicHttpAuthenticator extends HttpAuthenticator implements Authenticator
{

        private $user = "";
        private $pass = "";

        public function __construct($validator, $storage, $realm)
        {
                parent::__construct($validator, $storage, $realm);
                $this->initialize();
        }

        public function authenticated()
        {
                return $this->storage->exist($this->user);
        }

        public function getUser()
        {
                return $this->user;
        }

        public function login()
        {
                if (strlen($this->user) == 0) {
                        $this->unauthorized();
                } elseif (!$this->validator->authenticate()) {
                        $this->unauthorized();
                } else {
                        $this->storage->insert($this->user);
                }
        }

        public function logout()
        {
                $this->storage->remove($this->user);
                $this->unauthorized();
        }

        private function initialize()
        {
                if (isset($_SERVER['PHP_AUTH_USER']) && strlen($_SERVER['PHP_AUTH_USER']) != 0) {
                        $this->user = $_SERVER['PHP_AUTH_USER'];
                }
                if (isset($_SERVER['PHP_AUTH_PW']) && strlen($_SERVER['PHP_AUTH_PW']) != 0) {
                        $this->pass = $_SERVER['PHP_AUTH_PW'];
                }
                $this->validator->setCredentials($this->user, $this->pass);
        }

        private function unauthorized()
        {
                header(sprintf('WWW-Authenticate: Basic realm="%s"', $this->realm));
                header('HTTP/1.0 401 Unauthorized');
                if (isset($this->redirect)) {
                        header(sprintf("Location: %s", $this->redirect));
                } else {
                        die($this->message);
                }
        }

}
