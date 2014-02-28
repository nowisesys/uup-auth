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
 * Authenticator for hostname. The remote caller is considered as authenticated if a 
 * reverse lookup of IP-address in DNS matches the supplied hostname.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class HostnameAuthenticator implements Authenticator
{

        private $hostname;

        /**
         * Constructor. The hostname to authenticate default to localhost if $hostname
         * argument is missing.
         * 
         * @param string $hostname The hostname to authenticate.
         */
        public function __construct($hostname = null)
        {
                $this->hostname = isset($hostname) ? $hostname : 'localhost';
        }

        public function setHostname($hostname)
        {
                $this->hostname = $hostname;
        }

        public function authenticated()
        {
                return gethostbyaddr($_SERVER['REMOTE_ADDR']) == $this->hostname;
        }

        public function getUser()
        {
                return $this->hostname;
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
