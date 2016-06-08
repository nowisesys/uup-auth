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

namespace UUP\Authentication\Validator;

use UUP\Authentication\Exception;
use UUP\Authentication\Validator\CredentialValidator;

/**
 * PAM modules validator. 
 * 
 * Requires that the pam extension is loaded or that the pam_auth() function 
 * is defined.
 * 
 * <b>Warning:</b>
 * The web server account needs to have read access to i.e. /etc/shadow if doing 
 * local system account authentication. This may turn your application into an 
 * system security problem.
 *
 * @property-write bool $throws Throw exception upon failed login attempts.
 * @property-write bool $errlog Log failed login attempts to Apache error log.
 * @property-read string $errmsg Error message from last failed login attempt.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 * @link http://pecl.php.net/pam PAM extension project page.
 */
class PamValidator extends CredentialValidator
{

        private $_errmsg;
        private $_errlog = false;
        private $_throws = false;

        /**
         * Constructor.
         * @param string $user The username.
         * @param string $pass The password.
         * @throws Exception
         */
        public function __construct($user = "", $pass = "")
        {
                if (!extension_loaded("pam") && !extension_loaded("pam_auth")) {
                        if (!function_exists("pam_auth")) {
                                throw new Exception("The pam_auth() function is missing");
                        } else {
                                throw new Exception("The pam extension is not loaded");
                        }
                }
                parent::__construct($user, $pass);
        }

        public function __set($name, $value)
        {
                if ($name == 'errlog') {
                        $this->_errlog = (bool) $value;
                } elseif ($name == 'throws') {
                        $this->_throws = (bool) $value;
                }
        }

        public function __get($name)
        {
                if ($name == 'errmsg') {
                        return $this->_errmsg;
                }
        }

        public function authenticate()
        {
                if (!isset($this->_user) || strlen($this->_user) == 0) {
                        return false;
                }
                if (pam_auth($this->_user, $this->_pass, $this->_errmsg, false)) {
                        return true;
                } else {
                        $this->failed();
                        return false;
                }
        }

        private function failed()
        {
                if ($this->_errlog) {
                        error_log(sprintf("Failed authenticate %s: %s", $this->_user, $this->_errmsg));
                }
                if ($this->_throws) {
                        throw new Exception($this->_errmsg);
                }
                if ($this->_errmsg != 'Authentication failure (in pam_authenticate)') {
                        throw new Exception($this->_errmsg);
                }
        }

}
