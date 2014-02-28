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

namespace UUP\Authentication\Validator;

use UUP\Authentication\Exception;
use UUP\Authentication\Connector\LdapConnector;

/**
 * Validate against LDAP using a tree search. Passwords are normally stored encrypted
 * while the obtained password (from i.e. request parameters) are in plain text.
 * 
 * The LDAP search filter string should contain two string substitutions, the first is
 * a placeholder for username and the second for the password:
 * 
 * <code>
 * $filter = "(&(uid={%1})({passwd}={%2}))"
 * </code>
 * 
 * This example shows how to do an LDAP search to auhenticate a user ($user identified
 * by $pass below). Notice that we are binding to the LDAP tree in advance using a 
 * privileged admin account.
 * 
 * <code>
 * // Prepare:
 * $authenticator = new LdapSearchValidator($server, $basedn, $filter);
 * $authenticator->bind("admin", "secret");  // bind as privileged user
 * 
 * // Authenticate:
 * $authenticator->setCredentials($user, $pass);
 * $authenticator->authenticate();
 * </code>
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class LdapSearchValidator extends LdapConnector
{

        /**
         * The default LDAP search filter.
         */
        const filter = "(&(uid={%1})({passwd}={%2}))";

        private $basedn;
        private $filter;

        /**
         * Constructor.
         * @param string $server The LDAP server.
         * @param int $port Port on server.
         * @param string $basedn The LDAP search base DN.
         * @param string $filter The LDAP search filter.
         * @param array $options Associative array of miscellanous LDAP options.
         * @see ldap_set_options()
         */
        public function __construct($server, $basedn, $filter = self::filter, $port = 389, $options = array())
        {
                parent::__construct($server, $port, $options);
                $this->basedn = $basedn;
                $this->filter = $filter;
                $this->connect();
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                $this->disconnect();
        }

        /**
         * Set the LDAP search filter.
         * @param string $filter The LDAP search filter.
         * @see filter
         */
        public function setFilter($filter)
        {
                $this->filter = $filter;
        }

        public function authenticate()
        {
                $filter = sprintf($this->filter, $this->user, $this->pass);

                if (!($result = ldap_search($this->handle, $this->basedn, $filter))) {
                        throw new Exception(sprintf("Failed search LDAP: %s", ldap_error($this->handle)));
                }
                if (!($entries = ldap_count_entries($this->handle, $result))) {
                        ldap_free_result($result);
                        throw new Exception(sprintf("Failed fetch entries count: %s", ldap_error($this->handle)));
                }

                ldap_free_result($result);
                return $entries != 0;
        }

}
