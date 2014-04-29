<?php

/*
 * Copyright Error: on line 4, column 29 in Templates/Licenses/license-apache20.txt
  The string doesn't match the expected date/time format. The string to parse was: "2014-feb-27". The expected format was: "MMM d, yyyy". Anders Lövgren (Computing Department at BMC, Uppsala University).
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

namespace UUP\Authentication\Library\Authenticator;

use UUP\Authentication\Validator\Validator;

/**
 * Trait for HTTP authenticators. 
 * 
 * Provides uniform login/logout functionality for all HTTP authenticator 
 * classes using this trait. Defines the methods that implements the Authenticator 
 * interface.
 * 
 * The redirect property affects whether the browser is instructed to clear 
 * the username and password associated with the authentication realm.
 * 
 * @property-write string $redirect The redirect URL.
 * @property-write string $message Text to send if user hits Cancel button.
 * 
 * @author Anders Lövgren (Computing Department at BMC, Uppsala University)
 * @package UUP
 * @subpackage Authentication
 */
trait HttpAuthenticator
{

        /**
         * @var string The username.
         */
        private $user = "";
        /**
         * @var string The password.
         */
        private $pass = "";
        /**
         * @var Validator 
         */
        private $validator;
        /**
         * @var string The authentication realm.
         */
        private $realm;
        /**
         * @var string The redirect URL. 
         */
        private $redirect = null;
        /**
         * @var string 
         */
        private $message = "";

        /**
         * Configure the property bag for this trait.
         * 
         * @param Validator $validator The validator callback object.
         * @param string $realm The authentication realm.
         */
        private function config($validator, $realm)
        {
                $this->validator = $validator;
                $this->realm = $realm;
        }

        public function __set($name, $value)
        {
                switch ($name) {
                        case "redirect":
                                $this->redirect = (string) $value;
                                break;
                        case "message":
                                $this->message = (string) $value;
                                break;
                }
        }

        public function authenticated()
        {
                try {
                        return $this->validator->authenticate();
                } catch (\Exception $exception) {
                        error_log($exception->getMessage());
                        $this->unauthorized();
                }
        }

        public function getUser()
        {
                return $this->user;
        }

        public function login()
        {
                try {
                        if (strlen($this->user) == 0) {
                                $this->unauthorized();
                        } elseif (!$this->validator->authenticate()) {
                                $this->unauthorized();
                        }
                } catch (\Exception $exception) {
                        error_log($exception->getMessage());
                        $this->unauthorized();
                }
        }

        public function logout()
        {
                $this->unauthorized();
        }

}
