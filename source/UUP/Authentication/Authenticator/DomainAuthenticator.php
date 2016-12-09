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
use UUP\Authentication\Authenticator\HostnameAuthenticator;
use UUP\Authentication\Restrictor\Restrictor;

/**
 * Domain name authenticator.
 * 
 * Similar to HostnameAuthenticator, but accepts a domain name regex pattern 
 * to match remote host against.
 * 
 * <code>
 * $auth = new DomainAuthenticator('|^.*.(bmc.uu.se)$|');
 * if ($auth->accepted()) {
 *      printf("Welcome %s from %s\n", $auth->getSubject(), $auth->getDomain());
 * }
 * </code>
 *
 * The same domain authenticator can be used to match against multiple DNS 
 * domains. Capture patterns are optional unless getDomain() is used.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class DomainAuthenticator extends HostnameAuthenticator implements Restrictor, Authenticator
{

        /**
         * The matched hostname and domain.
         * @var array 
         */
        private $_matched;

        /**
         * Constructor.
         * @param string $accept The domain matching pattern.
         */
        public function __construct($accept)
        {
                parent::__construct($accept);
                $this->accepted();
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                parent::__destruct();
                $this->_matched = null;
        }

        /**
         * Check if peer is accepted.
         * @return boolean
         */
        public function accepted()
        {
                return $this->match(gethostbyaddr($_SERVER['REMOTE_ADDR']));
        }

        /**
         * Get peer hostname.
         * @return string
         */
        public function getSubject()
        {
                return $this->_matched[0];
        }

        /**
         * Get peer domain.
         * @return string
         */
        public function getDomain()
        {
                return $this->_matched[1];
        }

        /**
         * Check if remote hostname matches current domain pattern.
         * @param string $remote The remote hostname.
         * @return boolean
         */
        public function match($remote)
        {
                if (preg_match($this->_accept, $remote, $this->_matched) === 1) {
                        return true;
                } else {
                        $this->_matched = null;
                        return false;
                }
        }

}
