<?php

/*
 * Copyright (C) 2017 Anders Lövgren (Computing Department at BMC, Uppsala University).
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

use UUP\Authentication\Authenticator\FormAuthenticator;
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
 * @see FormAuthenticator
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
                $this->_validator = null;
                $this->_name = null;
                $this->_user = null;
                $this->_pass = null;
                $this->_accepted = null;
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
         * 
         * @param array $options Options for request parameters.
         * @param array $methods The accepted input methods, e.g. INPUT_POST.
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

        public function setNormalizer(callable $normalizer)
        {
                // ignore
        }

}
