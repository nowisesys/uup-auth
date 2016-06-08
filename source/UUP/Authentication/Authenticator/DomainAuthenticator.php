<?php

/*
 * Copyright (C) 2014-2015 Anders Lövgren (QNET/BMC CompDept).
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
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class DomainAuthenticator extends HostnameAuthenticator implements Restrictor, Authenticator
{

        private $_matched;

        public function accepted()
        {
                return $this->match(gethostbyaddr($_SERVER['REMOTE_ADDR']));
        }

        public function getSubject()
        {
                return $this->_matched;
        }

        /**
         * Check if remote hostname matches current domain pattern.
         * @param string $remote The remote hostname.
         * @return boolean
         */
        public function match($remote)
        {
                if (preg_match($this->_accept, $remote, $this->_matched) === 1) {
                        $this->_matched = $remote;
                        return true;
                } else {
                        $this->_matched = null;
                        return false;
                }
        }

}
