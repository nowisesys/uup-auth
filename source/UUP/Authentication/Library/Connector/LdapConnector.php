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

namespace UUP\Authentication\Library\Connector;

use UUP\Authentication\Exception;
use UUP\Authentication\Validator\CredentialValidator;

/**
 * The LDAP connector class. 
 * 
 * This abstract base class provides LDAP connectivity to derived LDAP 
 * authentication classes.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
abstract class LdapConnector extends CredentialValidator
{

        private $_server;
        private $_port;
        private $_options;
        protected $_handle;        // LDAP connection

        /**
         * Constructor.
         * @param string $server The LDAP server.
         * @param int $port Port on server.
         * @param array $options Associative array of miscellanous LDAP options.
         * @see ldap_set_options()
         */

        public function __construct($server, $port = 389, $options = array())
        {
                $this->_server = $server;
                $this->_port = $port;
                $this->_options = $options;
        }

        protected function connect()
        {
                if (!($this->_handle = ldap_connect($this->_server, $this->_port))) {
                        throw new Exception(sprintf("Failed connect to ''%s:%d''", $this->_server, $this->_port));
                }
                foreach ($this->_options as $option => $value) {
                        if (!ldap_set_option($this->_handle, $option, $value)) {
                                ldap_close($this->_handle);
                                throw new Exception(sprintf("Failed set option %s (value: %s)", (string) $option, (string) $value));
                        }
                }
        }

        /**
         * Bind to LDAP tree using supplied username and password.
         * @param string $user The username.
         * @param string $pass The password.
         * @throws Exception
         */
        public function bind($user, $pass)
        {
                if (!ldap_bind($this->_handle, $user, $pass)) {
                        ldap_close($this->_handle);
                        throw new Exception(sprintf("Failed bind as '%s' to %s:%d", $user, $this->_server, $this->_port));
                } else {
                        ldap_unbind($this->_handle);
                }
        }

        protected function disconnect()
        {
                if (is_resource($this->_handle)) {
                        ldap_close($this->_handle);
                }
        }

}
