<?php

/*
 * Copyright (C) Error: on line 5, column 33 in Templates/Licenses/license-apache20.txt
  The string doesn't match the expected date/time format. The string to parse was: "Aug 28, 2014". The expected format was: "yyyy-MMM-dd". Anders Lövgren (QNET/BMC CompDept).
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

namespace UUP\Authentication;

/**
 * The interface for all restrictor classes.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
interface Restrictor
{
        /**
         * Check that restriction subject is satisfied (e.g. user is logged in).
         * @return bool
         */
        function accepted();

        /**
         * Get subject (e.g. logged on user).
         * @return string
         */
        function getSubject();
}
