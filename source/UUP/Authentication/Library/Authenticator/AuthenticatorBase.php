<?php

/*
 * Copyright (C) 2014-2016 Anders Lövgren (QNET/BMC CompDept).
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

use UUP\Authentication\Authenticator\Authenticator;

/**
 * The base class for all authenticators.
 * 
 * Supports using the builder pattern when creating the authenticator object:
 * <code>
 * $authenticator = new XyzAuthenticator(...)
 *      ->control(Authenticator::required)
 *      ->name("The name")
 *      ->description("A longer text with more information");
 * </code>
 * 
 * @property int $control The access control for this authenticator.
 * @property string $name Short name for wrapped authenticator.
 * @property string $description Longer descriptive text for wrapped authenticator.
 * @property bool $visible This authenticator is visible for and selectable by remote user.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
abstract class AuthenticatorBase
{

        /**
         * The authenticator name.
         * @var string 
         */
        private $_name;
        /**
         * The authenticator description.
         * @var string 
         */
        private $_desc;
        /**
         * Is authenticator visible or hidden?
         * @var boolean 
         */
        private $_visible;
        /**
         * The authenticator control (sufficient, required or optional).
         * @var int 
         */
        private $_control;

        /**
         * Constructor.
         * 
         * The default authenticator is both visible and sufficient.
         */
        public function __construct()
        {
                $this->_visible = true;
                $this->_control = Authenticator::SUFFICIENT;
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                $this->_name = null;
                $this->_desc = null;
                $this->_visible = null;
                $this->_control = null;
        }

        public function __get($name)
        {
                switch ($name) {
                        case 'control':
                                return $this->_control;
                        case 'name':
                                return $this->_name;
                        case 'description':
                                return $this->_desc;
                        case 'visible':
                                return $this->_visible;
                }
        }

        public function __set($name, $value)
        {
                switch ($name) {
                        case 'control':
                                $this->control($value);
                                break;
                        case 'name':
                                $this->name($value);
                                break;
                        case 'description':
                                $this->description($value);
                                break;
                        case 'visible':
                                $this->visible($value);
                                break;
                }
        }

        /**
         * Sets the access control for this authenticator.
         * @param int $ctrl The access control.
         * @return Authenticator
         */
        public function control($ctrl)
        {
                $this->_control = (int) $ctrl;
                return $this;
        }

        /**
         * Sets the short name for wrapped authenticator.
         * @param string $text
         * @return Authenticator
         */
        public function name($text)
        {
                $this->_name = (string) $text;
                return $this;
        }

        /**
         * Sets a longer descriptive text for wrapped authenticator.
         * @param string $text
         * @return Authenticator
         */
        public function description($text)
        {
                $this->_desc = (string) $text;
                return $this;
        }

        /**
         * Set this authenticator can be selected by remote user as an authentication method.
         * @param bool $bool
         * @return Authenticator
         */
        public function visible($value)
        {
                $this->_visible = (bool) $value;
                return $this;
        }

        /**
         * This authenticator is suffcient for authentication.
         * @return bool
         */
        public function sufficient()
        {
                return $this->_control == Authenticator::SUFFICIENT;
        }

        /**
         * This authenticator is required for authentication.
         * @return bool
         */
        public function required()
        {
                return $this->_control == Authenticator::REQUIRED;
        }

        /**
         * This authenticator is optional for authentication.
         * @return bool
         */
        public function optional()
        {
                return $this->_control == Authenticator::OPTIONAL;
        }

}
