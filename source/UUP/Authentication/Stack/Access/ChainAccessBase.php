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

use UUP\Authentication\Stack\AuthenticatorChain,
    UUP\Authentication\Library\Authenticator\AuthenticatorBase,
    UUP\Authentication\Exception;

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
         * @var bool 
         */
        private $throw;

        /**
         * Constructor.
         * @param AuthenticatorChain $chain The authenticator chain object.
         * @param bool $throw Throw exception if get()/set() fail to read/write properties.
         */
        public function __construct($chain, $throw = false)
        {
                $this->chain = $chain;
                $this->throw = $throw;
        }

        public function __call($name, $arguments)
        {
                if (method_exists($this->chain, $name)) {
                        $this->chain->$name($arguments[0]);     // only single argument supported
                }
        }

        /**
         * Check if $name exist in this chain.
         * @param string $name
         * @return bool
         */
        protected function exist($name)
        {
                return $this->chain->exist($name);
        }

        /**
         * Get authenticator or chain matching $name.
         * @param string $name
         * @param string $class The calling class.
         * @return Authenticator|AuthenticatorChain
         */
        protected function get($name, $class)
        {
                // 
                // Object or array access: $chain->obj->_ or $chain['obj']['@']:
                // 
                if ($name == '@' || $name == '_') {
                        if ($this->chain instanceof AuthenticatorBase) {
                                return $this->chain;
                        } else {
                                return $this->chain->getArrayCopy();
                        }
                }

                if ($this->chain instanceof AuthenticatorChain) {
                        return new $class($this->chain->want($name));
                } elseif ($this->chain instanceof AuthenticatorBase) {
                        return $this->chain->$name;     // use magic accessor
                } elseif (property_exists($this->chain, $name)) {
                        return $this->chain->$name;     // public property
                } elseif (method_exists($this->chain, $name)) {
                        return $this->chain->$name();   // use function call
                } elseif (($func = sprintf("get%s", ucfirst($name))) && method_exists($this->chain, $func)) {
                        return $this->chain->$func();   // java style getName()
                } elseif ($this->throw) {
                        throw new Exception(sprintf('Failed get property %s on non-chain object (%s)', $name, get_class($this->chain)));
                }
        }

        /**
         * Set property or call member method or create sub chain.
         * 
         * This function performs three different tasks depending on whether this chain
         * is an chain or an object:
         * <ol>
         * <li>Set object property $name to $value.</li>
         * <li>Call member method $name with $value.</li>
         * <li>Insert object $value in this chain.</li>
         * </ol>
         * The last case (3) requires that this chain is an instance of AuthenticatorChain.
         * This function is kind of relaxed, its perfectly fine that the inserted value is
         * not an object at all.
         * 
         * This function throws an exception if the this chain refers to an immutable 
         * object that can't be modified (setting property in object fails).
         * 
         * @param string $name
         * @param mixed $value
         * @throws Exception
         */
        protected function set($name, $value)
        {
                if (property_exists($this->chain, $name)) {
                        $this->chain->$name = $value;           // set object property
                } elseif (method_exists($this->chain, $name)) {
                        $this->chain->$name($value);            // call member method
                } elseif ($this->chain instanceof AuthenticatorChain) {
                        $this->chain->insert($name, $value);    // insert in chain (relaxed)
                } elseif ($this->throw && ($this->chain->$name = $value) && ($this->chain->$name !== $value)) {
                        // Logic error that is hard to detect and will cause data loss.
                        throw new Exception(sprintf('Failed set property %s on immutable non-chain object (%s)', $name, get_class($this->chain)));
                }
        }

        /**
         * Remove object matching $name from this chain.
         * @param string $name
         */
        protected function remove($name)
        {
                $this->chain->remove($name);
        }

}
