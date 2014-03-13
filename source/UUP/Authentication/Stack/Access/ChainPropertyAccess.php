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
 * $chain = new ChainPropertyAccess(...);
 * $chain->auth1 = new *Authenticator(...);
 * $chain->auth2 = new *Authenticator(...);
 *   ...
 * $chain->chain1->authN = new *Authenticator(...); // <- Added in new chain
 *   ...
 * </code>
 * 
 * Properties in the authenticator class can be set using property access. If
 * a method exist with the same name, then it invoked if the given property
 * is missing:
 * <code>
 * $chain = new ChainPropertyAccess(...);
 * $chain->auth1 = $auth1;
 *   ...
 * // call $auth1->visible = true or $auth1->visible(true);
 * $chain->auth1->visible = true; 
 * </code>
 * 
 * Object methods can be invoked direct using property names. Methods calls 
 * are currently limited to single argument signatures:
 * <code>
 * $chain = new ChainPropertyAccess(...);
 * $chain->auth1 = $auth1;
 *   ...
 * $chain->auth1->visible(true);      // call $auth1->visible(true)
 * </code>
 * 
 * An object or chain can be accessed direct using the special '_' property:
 * <code>
 * $chain->auth1->_;    // Get unwrapped auth1 object.
 * $chain->chain1->_;   // Get chain as array.
 * </code>
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class ChainPropertyAccess extends ChainAccessBase
{

        public function __get($name)
        {
                return parent::get($name, __CLASS__);
        }

        public function __set($name, $value)
        {
                parent::set($name, $value);
        }

        public function __isset($name)
        {
                return parent::exist($name);
        }

        public function __unset($name)
        {
                parent::remove($name);
        }

}
