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

namespace UUP\Authentication\Library\Connector;

use UUP\Authentication\Exception,
    UUP\Authentication\Validator\CredentialValidator;

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

        private $server;
        private $port;
        private $options;
        protected $handle;        // LDAP connection

        /**
         * Constructor.
         * @param string $server The LDAP server.
         * @param int $port Port on server.
         * @param array $options Associative array of miscellanous LDAP options.
         * @see ldap_set_options()
         */

        public function __construct($server, $port = 389, $options = array())
        {
                $this->server = $server;
                $this->port = $port;
                $this->options = $options;
        }

        protected function connect()
        {
                if (!($this->handle = ldap_connect($this->server, $this->port))) {
                        throw new Exception(sprintf("Failed connect to ''%s:%d''", $this->server, $this->port));
                }
                foreach ($this->options as $option => $value) {
                        if (!ldap_set_option($this->server, $option, $value)) {
                                ldap_close($this->handle);
                                throw new Exception("Failed set option.");
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
                if (!ldap_bind($this->handle, $user, $pass)) {
                        ldap_close($this->handle);
                        throw new Exception(sprintf("Failed bind as '%s' to %s:%d", $user, $this->server, $this->port));
                } else {
                        ldap_unbind($this->handle);
                }
        }

        protected function disconnect()
        {
                if (is_resource($this->handle)) {
                        ldap_close($this->handle);
                }
        }

}
