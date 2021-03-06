<?php

/*
 * Copyright (C) 2014-2015 Anders Lövgren (Nowise Systems/Uppsala University).
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
use UUP\Authentication\Library\Connector\LdapConnector;

/**
 * Validate against LDAP using a simple bind.
 *
 * @author Anders Lövgren (Nowise Systems/Uppsala University)
 */
class LdapBindValidator extends LdapConnector
{

        /**
         * Constructor.
         * @param string $server The LDAP server.
         * @param int $port Port on server.
         * @param array $options Associative array of miscellanous LDAP options.
         * @see ldap_set_options()
         */
        public function __construct($server, $port = 389, $options = array())
        {
                parent::__construct($server, $port, $options);
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                $this->disconnect();
        }

        /**
         * Authenticate using currently set credentials. Returns true if authentication succeed.
         * @return bool 
         * @throws Exception
         */
        public function authenticate()
        {
                if (!isset($this->_user) || strlen($this->_user) == 0) {
                        return false;
                }
                if (!isset($this->_handle)) {
                        $this->connect();
                }
                try {
                        $this->bind($this->_user, $this->_pass);
                        return true;
                } catch (Exception $e) {
                        error_log(sprintf("%s in %s on line %d", $e->getMessage(), __METHOD__, __LINE__));
                        return false;
                }
        }

}
