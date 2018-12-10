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
use UUP\Authentication\Validator\Validator;

/**
 * Client for request authenticator.
 * 
 * @author Anders Lövgren (Nowise Systems/Uppsala University)
 * @package UUP
 * @subpackage Authentication
 * 
 * @see RequestAuthenticator
 * @see FormAuthenticator
 */
class RequestClient
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
         * The subject normalizer callback.
         * @var callable 
         */
        protected $_normalizer;
        /**
         * The default domain.
         * @var string 
         */
        private $_domain;

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

                $this->_normalizer = null;
                $this->_domain = null;
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

                if (isset($options['domain'])) {
                        $this->_domain = $options['domain'];
                }

                if (!empty($this->_user)) {
                        $this->setNormalizer(function($user) {
                                return $this->getPrincipal($user);
                        });
                }
                if (isset($this->_normalizer)) {
                        $this->_user = call_user_func($this->_normalizer, $this->_user);
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

        /**
         * Set subject normalizer.
         * 
         * <code>
         * // 
         * // Append default domain:
         * // 
         * $auth->setNormalizer(function($user) use($domain) {
         *      if (strpos($user, '@') === false) {
         *              return sprintf("%s@%s", $user, $domain);
         *      } else {
         *              return $user;
         *      }
         * });
         * </code>
         * 
         * @param callable $normalizer The normalizer callback.
         */
        public function setNormalizer(callable $normalizer)
        {
                $this->_normalizer = $normalizer;
        }

        /**
         * Get normlized username.
         * 
         * This function passes the username argument through the current set
         * normalizer function. The default normalizer is a noop.
         * 
         * @param string $user The username to normalize.
         * @return string
         */
        public function getNormalized($user)
        {
                return call_user_func($this->_normalizer, $user);
        }

        /**
         * Set default user domain.
         * @param string $domain The default user domain.
         */
        public function setDomain($domain)
        {
                $this->_domain = $domain;
        }

        /**
         * Get user principal.
         * @param string $user The username.
         */
        private function getPrincipal($user)
        {
                if (strpos($user, '@') !== false) {
                        return $user;
                }
                if (!isset($this->_domain)) {
                        return $user;
                } else {
                        return sprintf("%s@%s", $user, $this->_domain);
                }
        }

}
