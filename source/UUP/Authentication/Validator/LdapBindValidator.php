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

/**
 * Validate against LDAP using a simple bind.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 */
class LdapBindValidator extends LdapConnector
{

        public function __construct($server, $port = 389, $options = array())
        {
                parent::__construct($server, $port, $options);
                $this->connect();
        }

        public function __destruct()
        {
                $this->disconnect();
        }

        public function authenticate()
        {
                try {
                        $this->bind($this->user, $this->pass);
                        return true;
                } catch (Exception $e) {
                        return false;
                }
        }

}
