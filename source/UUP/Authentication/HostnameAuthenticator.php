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

use UUP\Authentication\Library\Authenticator\AuthenticatorBase;

/**
 * Hostname authenticator. 
 * 
 * The remote caller is considered as authenticated if a reverse lookup of 
 * IP-address in DNS matches the supplied hostname.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class HostnameAuthenticator extends AuthenticatorBase
{

        const localhost = 'localhost';

        private $accept;

        /**
         * Constructor. The hostname to authenticate default to localhost if 
         * the $accept argument is missing.
         * @param string $accept The hostname to authenticate.
         */
        public function __construct($accept = self::localhost)
        {
                $this->accept = $accept;
        }

        /**
         * Set the hostname to authenticate.
         * @param string $accept The hostname to authenticate.
         */
        public function setHostname($accept)
        {
                $this->accept = $accept;
        }

        public function authenticated()
        {
                return gethostbyaddr($_SERVER['REMOTE_ADDR']) == $this->accept;
        }

        public function getUser()
        {
                return $this->accept;
        }

        public function login()
        {
                // ignore
        }

        public function logout()
        {
                // ignore
        }

}
