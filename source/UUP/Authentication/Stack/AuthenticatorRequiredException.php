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

namespace UUP\Authentication\Stack;

use RuntimeException;
use UUP\Authentication\Library\Authenticator\AuthenticatorBase;

/**
 * Exception thrown when authentication against a required authenticator failed.
 *
 * @property-read AuthenticatorBase $authenticator The authenticator throwing exception.
 * @author Anders Lövgren (Nowise Systems/Uppsala University)
 * @package UUP
 * @subpackage Authentication
 */
class AuthenticatorRequiredException extends RuntimeException
{

        /**
         * Constructor.
         * @param AuthenticatorBase $authenticator
         */
        public function __construct($authenticator)
        {
                parent::__construct(sprintf("Required authenticator %s (%s) failed on restriction %s\n", $authenticator->name, get_class($authenticator), (string) $authenticator));
                $this->authenticator = $authenticator;
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                $this->authenticator = null;
        }

}
