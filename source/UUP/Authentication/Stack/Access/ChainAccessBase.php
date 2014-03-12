<?php

/*
 * Copyright (C) 2014 Anders Lövgren (Computing Department at BMC, Uppsala University).
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

/**
 * Base class for chain access implementations.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class ChainAccessBase
{

        /**
         * @var AuthenticatorChain 
         */
        private $chain;

        /**
         * Constructor.
         * @param AuthenticatorChain $chain The authenticator chain object.
         */
        public function __construct($chain)
        {
                $this->chain = $chain;
        }

        public function __call($name, $arguments)
        {
                if (method_exists($this->chain, $name)) {
                        $this->chain->$name($arguments[0]);     // only single argument supported
                }
        }

        protected function exist($name)
        {
                $this->chain->exist($name);
        }

        protected function get($name)
        {
                return $this->chain->want($name);
        }

        protected function set($name, $value)
        {
                if (property_exists($this->chain, $name)) {
                        $this->chain->$name = $value; // $chain[$offset] = $value;
                } elseif (method_exists($this->chain, $name)) {
                        $this->chain->$name($value);  // call method using array subscript
                } else {
                        $this->chain->insert($name, $value);
                }
        }

        protected function remove($name)
        {
                $this->chain->remove($offset);
        }

}
