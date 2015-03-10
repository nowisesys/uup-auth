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

namespace UUP\Authentication\Storage;

/**
 * The interface for persistent storage.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
interface Storage
{

        /**
         * Add username to persistent storage.
         * @param string $user The username.
         * @return bool
         */
        function insert($user);

        /**
         * Remove username from persistent storage.
         * @param string $user The username.
         * @return bool 
         */
        function remove($user);

        /**
         * Check if username exist in persistent storage. Return true if user is present in
         * the storage backend.
         * @param string $user The username.
         * @return bool
         */
        function exist($user);
}
