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

namespace UUP\Authentication\Authenticator;

use UUP\Authentication\Authenticator\Authenticator;
use UUP\Authentication\Library\Authenticator\AuthenticatorBase;
use UUP\Authentication\Restrictor\Restrictor;

/**
 * Hostname authenticator. 
 * 
 * The remote host is considered as authenticated if a reverse lookup of 
 * IP-address in DNS matches the supplied hostname.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class HostnameAuthenticator extends AuthenticatorBase implements Restrictor, Authenticator
{

        /**
         * Default hostname to accept.
         */
        const LOCALHOST = 'localhost';

        /**
         * The hostname to accept.
         * @var string 
         */
        protected $_accept;

        /**
         * Constructor. The hostname to authenticate default to localhost if 
         * the $accept argument is missing.
         * @param string $accept The hostname to authenticate.
         */
        public function __construct($accept = self::LOCALHOST)
        {
                parent::__construct();

                $this->_accept = $accept;
                $this->visible(false);
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                parent::__destruct();

                $this->_accept = null;
        }

        /**
         * Set the hostname to authenticate.
         * @param string $accept The hostname to authenticate.
         */
        public function setHostname($accept)
        {
                $this->_accept = $accept;
        }

        /**
         * Check if peer is accepted.
         * @return boolean
         */
        public function accepted()
        {
                return gethostbyaddr($_SERVER['REMOTE_ADDR']) == $this->_accept;
        }

        /**
         * Get authenticated hostname.
         * @return string
         */
        public function getSubject()
        {
                return $this->_accept;
        }

        /**
         * Trigger hostname login (noop).
         */
        public function login()
        {
                // ignore
        }

        /**
         * Trigger hostname logout (noop).
         */
        public function logout()
        {
                // ignore
        }

}
