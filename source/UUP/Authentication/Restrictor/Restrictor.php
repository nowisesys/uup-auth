<?php

/*
 * Copyright (C) 2014-2017 Anders Lövgren (Nowise Systems/Uppsala University).
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

namespace UUP\Authentication\Restrictor;

/**
 * The interface for all restrictor classes.
 * 
 * @author Anders Lövgren (Nowise Systems/Uppsala University)
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

        /**
         * Set subject normalizer.
         * @param callable $normalizer The normalizer callback.
         */
        function setNormalizer(callable $normalizer);
}
