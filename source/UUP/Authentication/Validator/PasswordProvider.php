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
 * Password lookup interface.
 * 
 * Any validator class with access to an account database (i.e. LDAP) could 
 * implement this interface to extend its capabilities and make it useful 
 * together with authenticator classes that uses hashing algorithms. 
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
interface PasswordProvider
{

        /**
         * Return password for this user.
         */
        function getPassword($user);
}
