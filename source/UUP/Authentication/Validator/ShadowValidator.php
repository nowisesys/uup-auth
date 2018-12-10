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

namespace UUP\Authentication\Validator;

use UUP\Authentication\Exception;
use UUP\Authentication\Validator\CredentialValidator;

/**
 * User account validation against the shadow password file. 
 * 
 * The shadow password file has to be readable by the user account the web 
 * server is running under:
 * 
 * <code>
 * # Grant access to web server user using POSIX Access Control Lists (ACLs) on Gentoo Linux:
 * bash$> setfacl -m u:apache:r /etc/shadow
 * </code>
 *
 * <b>Warning:</b>
 * The web server account needs to have read access to i.e. /etc/shadow if doing 
 * local system account authentication. This may turn your application into an 
 * system security problem.
 * 
 * @property-write string $shadow Set the shadow password file to use.
 * 
 * @author Anders Lövgren (Nowise Systems/Uppsala University)
 * @package UUP
 * @subpackage Authentication
 */
class ShadowValidator extends CredentialValidator
{

        /**
         * The gecos information delimiter.
         */
        const DELIMITER = ':';

        /**
         * Shadow password file path.
         * @var string 
         */
        private $_shadow;

        /**
         * Constructor.
         * @param string $file Shadow password file path.
         */
        public function __construct($file = '/etc/shadow')
        {
                $this->_shadow = $file;
        }

        public function __set($name, $value)
        {
                if ($name == 'shadow') {
                        $this->_shadow = (string) $value;
                }
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
                if (($pass = $this->password()) != null) {
                        return crypt($this->_pass, $pass) == $pass;
                } else {
                        return false;
                }
        }

        /**
         * Get encrypted password.
         * 
         * Search the shadow file for currently defined user and return the
         * encrypted password. Returns null if not found. Throws exception on
         * read permission error.
         * 
         * @return string
         * @throws Exception
         */
        private function password()
        {
                if (($handle = fopen($this->_shadow, "r"))) {
                        while (($line = fgets($handle))) {
                                if (strstr($line, $this->_user)) {
                                        $parts = explode(self::DELIMITER, $line);
                                        return $parts[1];
                                }
                        }
                        fclose($handle);
                        return null;
                } else {
                        throw new Exception(sprintf("Failed open %s", $this->_shadow));
                }
        }

}
