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
 * $chain = new ChainArrayAccess(...);
 * $chain['auth1'] = new *Authenticator(...);
 * $chain['auth2'] = new *Authenticator(...);
 *   ...
 * $chain['chain1']['authN'] = new *Authenticator(...); // <- Added in new chain
 *   ...
 * </code>
 * 
 * Properties in the authenticator class can be set using array subscript. If
 * a method exist with the subscript name, then it invoked if the named property
 * is missing:
 * <code>
 * $chain = new ChainArrayAccess(...);
 * $chain['auth1'] = $auth1;
 *   ...
 * // call $auth1->visible = true or $auth1->visible(true);
 * $chain['auth1']['visible'] = true; 
 * </code>
 * 
 * Object methods can be invoked direct using array subscript. Methods calls 
 * are currently limited to single argument signatures:
 * <code>
 * $chain = new ChainArrayAccess(...);
 * $chain['auth1'] = $auth1;
 *   ...
 * $chain['auth1']->visible(true);      // call $auth1->visible(true)
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

        public function __call($name, $arguments)
        {
                if (method_exists($this->chain, $name)) {
                        $this->chain->$name($arguments[0]);     // only single argument supported
                }
        }

        public function offsetExists($offset)
        {
                return $this->chain->exist($offset);
        }

        public function offsetGet($offset)
        {
                return new self($this->chain->want($offset));
        }

        public function offsetSet($offset, $value)
        {
                if (property_exists($this->chain, $offset)) {
                        $this->chain->$offset = $value; // $chain[$offset] = $value;
                } elseif (method_exists($this->chain, $offset)) {
                        $this->chain->$offset($value);  // call method using array subscript
                } else {
                        $this->chain->insert($offset, $value);
                }
        }

        public function offsetUnset($offset)
        {
                $this->chain->remove($offset);
        }

}
