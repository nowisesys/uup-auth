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

namespace UUP\Authentication\Authenticator;

/**
 * The interface for all authenticator classes.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
interface Authenticator
{

        /**
         * Not used.
         */
        const OPTIONAL = 1;
        /**
         * This authenticator is sufficient for successful authentication.
         */
        const SUFFICIENT = 2;
        /**
         * This authenticator is required for successful authentication. 
         */
        const REQUIRED = 3;

        /**
         * Perform login for this authenticator.
         */
        function login();

        /**
         * Perform logout for this authenticator.
         */
        function logout();
}
