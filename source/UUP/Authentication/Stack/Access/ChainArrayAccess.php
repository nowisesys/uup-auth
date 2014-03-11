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
 * Provides array access to authenticator chain.
 *
 * New chains are automatic created whenever a new multi-dimensional array
 * index is used:
 * <code>
 * $array = new ChainArrayAccess($chain);
 * $array['auth1'] = new *Authenticator(...);
 * $array['auth2'] = new *Authenticator(...);
 *   ...
 * $array['chain1']['authN'] = new *Authenticator(...); // <- Added in new chain
 *   ...
 * </code>
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class ChainArrayAccess implements \ArrayAccess
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

        public function offsetExists($offset)
        {
                return $this->chain->exist($offset);
        }

        public function offsetGet($offset)
        {
                return new ChainArrayAccess($this->chain->want($offset));
        }

        public function offsetSet($offset, $value)
        {
                $this->chain->insert($offset, $value);
        }

        public function offsetUnset($offset)
        {
                $this->chain->remove($offset);
        }

}
