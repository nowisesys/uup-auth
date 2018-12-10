<?php

/*
 * Copyright (C) 2014-2017 Anders Lövgren (Nowise Systems/Uppsala University).
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
 * Initialize with the accepted hostname. The remote peer is considered to be 
 * authenticated if a reverse DNS-lookup mathes the accepted hostname. The 
 * accepted hostname can be modified. 
 * 
 * To repeatedly check remote hostnames against the accepted hostname, call 
 * match() passing each remote hostname. Use accepted() to authenticate remote 
 * peer. Hostname of remote peer is resolved on-demand so that initialize multiple
 * objects causes no delay until actually used.
 *
 * @author Anders Lövgren (Nowise Systems/Uppsala University)
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
         * Constructor. 
         * 
         * The hostname to authenticate default to localhost if the $accept 
         * argument is missing.
         * 
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

        public function __get($name)
        {
                switch ($name) {
                        case '_remote':
                                return $this->_remote = gethostbyaddr($_SERVER['REMOTE_ADDR']);
                        default :
                                return parent::__get($name);
                }
        }

        public function __set($name, $value)
        {
                switch ($name) {
                        case '_remote':
                                $this->_remote = $value;
                        default:
                                parent::__set($name, $value);
                }
        }

        /**
         * Set remote peer hostname for authentication.
         * @param string $hostname The peer hostname.
         */
        public function setRemote($hostname)
        {
                $this->_remote = $hostname;
        }

        /**
         * Get remote peer hostname for authentication.
         * @return string 
         */
        public function getRemote()
        {
                return $this->_remote;
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
         * Get the hostname to authenticate.
         * @return string
         */
        public function getHostname()
        {
                return $this->_accept;
        }

        /**
         * Check if peer is accepted.
         * @return boolean
         */
        public function accepted()
        {
                return $this->_accept == $this->_remote;
        }

        /**
         * Check if remote hostname matches current hostname.
         * @param string $remote The remote hostname.
         * @return boolean
         */
        public function match($remote)
        {
                return $this->_accept == $remote;
        }

        /**
         * Get authenticated hostname.
         * @return string
         */
        public function getSubject()
        {
                return $this->_remote;
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
