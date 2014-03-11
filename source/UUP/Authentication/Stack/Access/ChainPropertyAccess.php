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
 * Provides property access to authenticator chain.
 *
 * New chains are automatic created whenever a new level of indirection
 * is entered:
 * <code>
 * $object = new ChainArrayAccess($chain);
 * $object->auth1 = new *Authenticator(...);
 * $object->auth2 = new *Authenticator(...);
 *   ...
 * $object->chain1->authN = new *Authenticator(...); // <- Added in new chain
 *   ...
 * </code>
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class ChainPropertyAccess
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

        public function __get($name)
        {
                return new ChainPropertyAccess($this->chain->want($name));
        }

        public function __set($name, $value)
        {
                $this->chain->insert($name, $value);
        }

        public function __isset($name)
        {
                return $this->chain->exist($name);
        }

        public function __unset($name)
        {
                $this->chain->remove($name);
        }

}
