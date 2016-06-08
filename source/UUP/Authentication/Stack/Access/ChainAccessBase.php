<?php

/*
 * Copyright (C) 2014-2015 Anders Lövgren (Computing Department at BMC, Uppsala University).
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
use UUP\Authentication\Exception;
use UUP\Authentication\Restrictor\Restrictor;
use UUP\Authentication\Stack\AuthenticatorChain;

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
        private $_chain;
        /**
         * @var bool 
         */
        private $_throw;

        /**
         * Constructor.
         * @param AuthenticatorChain $chain The authenticator chain object.
         * @param bool $throw Throw exception if get()/set() fail to read/write properties.
         */
        public function __construct($chain, $throw = false)
        {
                $this->_chain = $chain;
                $this->_throw = $throw;
        }

        public function __call($name, $arguments)
        {
                if (method_exists($this->_chain, $name)) {
                        $this->_chain->$name($arguments[0]);     // only single argument supported
                }
        }

        /**
         * Check if $name exist in this chain.
         * @param string $name
         * @return bool
         */
        protected function exist($name)
        {
                return $this->_chain->exist($name);
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
                        if ($this->_chain instanceof Restrictor) {
                                return $this->_chain;
                        } else {
                                return $this->_chain->getArrayCopy();
                        }
                }

                if ($this->_chain instanceof AuthenticatorChain) {
                        return new $class($this->_chain->want($name), $this->_throw);
                } elseif ($this->_chain instanceof Restrictor) {
                        return $this->_chain->$name;     // use magic accessor
                } elseif (property_exists($this->_chain, $name)) {
                        return $this->_chain->$name;     // public property
                } elseif (method_exists($this->_chain, $name)) {
                        return $this->_chain->$name();   // use function call
                } elseif (($func = sprintf("get%s", ucfirst($name))) && method_exists($this->_chain, $func)) {
                        return $this->_chain->$func();   // java style getName()
                } elseif ($this->_throw) {
                        throw new Exception(sprintf('Failed get property %s on non-chain object (%s)', $name, get_class($this->_chain)));
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
                if (property_exists($this->_chain, $name)) {
                        $this->_chain->$name = $value;           // set object property
                } elseif (method_exists($this->_chain, $name)) {
                        $this->_chain->$name($value);            // call member method
                } elseif ($this->_chain instanceof AuthenticatorChain) {
                        $this->_chain->insert($name, $value);    // insert in chain (relaxed)
                } elseif ($this->_throw && ($this->_chain->$name = $value) && ($this->_chain->$name !== $value)) {
                        // Logic error that is hard to detect and will cause data loss.
                        throw new Exception(sprintf('Failed set property %s on immutable non-chain object (%s)', $name, get_class($this->_chain)));
                }
        }

        /**
         * Remove object matching $name from this chain.
         * @param string $name
         */
        protected function remove($name)
        {
                $this->_chain->remove($name);
        }

}
