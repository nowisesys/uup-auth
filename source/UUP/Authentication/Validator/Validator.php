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

/**
 * Interface for all validator classes.
 * 
 * @author Anders Lövgren (Nowise Systems/Uppsala University)
 * @package UUP
 * @subpackage Authentication
 */
interface Validator
{

        /**
         * Set credentials for authentication.
         * @param string $user The username.
         * @param string $pass The password.
         */
        function setCredentials($user, $pass);

        /**
         * Authenticate using currently set credentials. Returns true if authentication succeed.
         * @return bool 
         * @throws Exception
         */
        function authenticate();
}
