<?php

/*
 * Copyright (C) 2014-2017 Anders Lövgren (Computing Department at BMC, Uppsala University).
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
use UUP\Authentication\Restrictor\Restrictor;

/**
 * Null authenticator.
 * 
 * An authenticator that never accepts login and always return false from 
 * accepted(). This class is meant to be used for nuking login by adding it 
 * to the authenticator stack and setting it as required. Usage case might 
 * be if the system is taken down for service.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class NullAuthenticator implements Restrictor, Authenticator
{

        /**
         * Get authentication status (always false).
         * @return boolean
         */
        public function accepted()
        {
                return false;
        }

        /**
         * Get authenticator subject (always an empty string).
         * @return string
         */
        public function getSubject()
        {
                return "";
        }

        /**
         * Trigger login (noop).
         */
        public function login()
        {
                // ignore
        }

        /**
         * Trigger logout (noop).
         */
        public function logout()
        {
                // ignore
        }

        public function setNormalizer(callable $normalizer)
        {
                // ignore
        }

}
