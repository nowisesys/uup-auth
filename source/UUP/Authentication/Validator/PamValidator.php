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

/**
 * PAM modules validator. Requires that the pam extension is loaded or that
 * the pam_auth() function is defined.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class PamValidator extends CredentialValidator
{

        /**
         * Constructor.
         * @param string $user The username.
         * @param string $pass The password.
         * @throws Exception
         */
        public function __construct($user = "", $pass = "")
        {
                if (!extension_loaded("pam")) {
                        if (!function_exists("pam_auth")) {
                                throw new Exception("The pam_auth() function is missing");
                        } else {
                                throw new Exception("The pam extension is not loaded");
                        }
                }
                parent::__construct($user, $pass);
        }

        public function authenticate()
        {
                $error = "";
                return pam_auth($this->user, $this->pass, &$error);
        }

}
