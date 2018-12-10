<?php

/*
 * Copyright (C) 2014-2016 Anders Lövgren (Nowise Systems/Uppsala University).
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
 * @author Anders Lövgren (Nowise Systems/Uppsala University)
 * @package UUP
 * @subpackage Authentication
 */
abstract class LdapConnector extends CredentialValidator
{

        /**
         * The LDAP server name.
         * @var string 
         */
        private $_server;
        /**
         * The LDAP server port.
         * @var int 
         */
        private $_port;
        /**
         * Miscellanous LDAP options.
         * @var array 
         */
        private $_options;
        /**
         * The LDAP connection
         * @var resource 
         */
        protected $_handle;

        /**
         * Constructor.
         * 
         * @param string $server The LDAP server name.
         * @param int $port The LDAP server port.
         * @param array $options Miscellanous LDAP options.
         * @see ldap_set_options()
         */
        public function __construct($server, $port = 389, $options = array())
        {
                $this->_server = $server;
                $this->_port = $port;
                $this->_options = $options;
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                parent::__destruct();

                $this->_handle = null;
                $this->_options = null;
                $this->_port = null;
                $this->_server = null;
        }

        /**
         * Open LDAP connection.
         * @throws Exception
         */
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
         * Bind LDAP connection.
         * 
         * Binding is done using supplied username and password credentials. Use
         * this method to check authentication.
         * 
         * @param string $user The username.
         * @param string $pass The password.
         * 
         * @throws Exception
         */
        public function bind($user, $pass)
        {
                if (!@ldap_bind($this->_handle, $user, $pass)) {
                        ldap_close($this->_handle);
                        throw new Exception(sprintf("Failed bind as '%s' to %s:%d", $user, $this->_server, $this->_port));
                } else {
                        ldap_unbind($this->_handle);
                }
        }

        /**
         * Disconnect LDAP connection.
         */
        protected function disconnect()
        {
                if (is_resource($this->_handle)) {
                        ldap_close($this->_handle);
                }
        }

}
