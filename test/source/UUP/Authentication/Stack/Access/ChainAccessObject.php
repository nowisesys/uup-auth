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

namespace UUP\Authentication\Stack\Access;

use UUP\Authentication\Authenticator\Authenticator;
use UUP\Authentication\Restrictor\Restrictor;

/**
 * Simple class for testing chain access.
 * @property int $prop
 */
class ChainAccessObject implements Authenticator, Restrictor
{

        private $prop;
        private $func;

        public function __get($name)
        {
                if ($name == 'prop') {
                        return $this->prop;
                }
        }

        public function __set($name, $value)
        {
                if ($name == 'prop') {
                        $this->prop = $value;
                }
        }

        public function func($value)
        {
                $this->func = $value;
        }

        public function accepted()
        {
                
        }

        public function getSubject()
        {
                
        }

        public function login()
        {
                
        }

        public function logout()
        {
                
        }

        public function setNormalizer(callable $normalizer)
        {
                
        }

}
