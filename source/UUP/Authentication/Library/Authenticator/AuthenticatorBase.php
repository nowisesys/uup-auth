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

namespace UUP\Authentication\Library\Authenticator;

use UUP\Authentication\Authenticator;

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
 * @property-read int $control The access control for this authenticator.
 * @property-read string $name Short name for wrapped authenticator.
 * @property-read string $description Longer descriptive text for wrapped authenticator.
 * @property-read bool $visible This authenticator is visible for and selectable by remote user.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
abstract class AuthenticatorBase implements Authenticator
{

        private $ctrl;
        private $name;
        private $desc;
        private $visible = true;

        public function __get($name)
        {
                switch ($name) {
                        case 'control':
                                return $this->ctrl;
                        case 'name':
                                return $this->name;
                        case 'description':
                                return $this->desc;
                        case 'visible':
                                return $this->visible;
                }
        }

        /**
         * Sets the access control for this authenticator.
         * @param int $ctrl The access control.
         * @return Authenticator
         */
        public function control($ctrl)
        {
                $this->ctrl = (int) $ctrl;
                return $this;
        }

        /**
         * Sets the short name for wrapped authenticator.
         * @param string $text
         * @return Authenticator
         */
        public function name($text)
        {
                $this->name = (string) $text;
                return $this;
        }

        /**
         * Sets a longer descriptive text for wrapped authenticator.
         * @param string $text
         * @return Authenticator
         */
        public function description($text)
        {
                $this->desc = (string) $text;
                return $this;
        }

        /**
         * Set this authenticator can be selected by remote user as an authentication method.
         * @param bool $bool
         * @return Authenticator
         */
        public function visible($value)
        {
                $this->visible = (bool) $value;
                return $this;
        }

        /**
         * This authenticator is suffcient for authentication.
         * @return bool
         */
        public function sufficient()
        {
                return $this->ctrl == self::sufficient;
        }

        /**
         * This authenticator is required for authentication.
         * @return bool
         */
        public function required()
        {
                return $this->ctrl == self::required;
        }

}