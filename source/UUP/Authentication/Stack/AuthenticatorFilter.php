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

use RecursiveArrayIterator;
use RecursiveIteratorIterator;
use UUP\Authentication\Authenticator\Authenticator;
use UUP\Authentication\Exception;
use UUP\Authentication\Library\Authenticator\AuthenticatorBase;
use UUP\Authentication\Stack\AuthenticatorChain;
use UUP\Authentication\Stack\Filter\ArrayKeyFilterIterator;
use UUP\Authentication\Stack\Filter\AuthenticatorFilterIterator;
use UUP\Authentication\Stack\Filter\ChainFilterIterator;

/**
 * Authenticator object and chain filtering class.
 * 
 * Provides filtering of the supplied authenticator chain. The filtering 
 * is performed only on the intermediate level of the chain. For in depth 
 * search, use the AuthenticatorSearch class.
 * 
 * @author Anders Lövgren (Nowise Systems/Uppsala University)
 * @package UUP
 * @subpackage Authentication
 */
class AuthenticatorFilter
{

        /**
         * @var array 
         */
        protected $_chain;

        /**
         * Constructor.
         * @param AuthenticatorChain|array $chain The authenticator chain.
         * @throws Exception
         */
        public function __construct($chain)
        {
                if (!extension_loaded('SPL')) {
                        throw new Exception('The SPL extension is not loaded');
                }
                if ($chain instanceof AuthenticatorChain) {
                        $this->_chain = $chain->getArrayCopy();
                } else {
                        $this->_chain = $chain;
                }
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                $this->_chain = null;
        }

        /**
         * Get iterator for all authenticators with matching key.
         * 
         * This function is non-linear as it search and returns result from
         * any child chain also. Use get() for direct access within this 
         * chain.
         * 
         * In most cases, all authenticators and chains are assigned unique
         * keys so that this code snippet will give access to the only 
         * decorated authenticator object:
         * 
         * <code>
         * $filter = new AuthenticatorFilter($chain);
         * $object = $filter->find($key)->current();
         * </code>
         * 
         * @param string $key The key name.
         * @return Authenticator[]|AuthenticatorFilterIterator
         */
        public function find($key)
        {
                return $this->authenticator($key);
        }

        /**
         * Get iterator for all chains with matching key.
         * 
         * This function is non-linear as it search and returns result from
         * any child chain also. Use get() for direct access within this 
         * chain.
         * 
         * In most cases, all authenticators and chains are assigned unique
         * keys so that this code snippet will give access to the only 
         * decorated authenticator object:
         * 
         * <code>
         * $object = $chain->chain($key)->current();
         * </code>
         * 
         * @param string $key The chain key.
         * @return AuthenticatorChain|ChainFilterIterator|array
         */
        public function chain($key)
        {
                return self::rewind(
                        new ChainFilterIterator(
                        new ArrayKeyFilterIterator(
                        new RecursiveIteratorIterator(
                        new RecursiveArrayIterator($this->_chain), RecursiveIteratorIterator::SELF_FIRST
                        ), $key)
                ));
        }

        /**
         * Get iterator for all authenticators with matching key.
         * 
         * This function is non-linear as it search and returns result from
         * any child chain also. Use get() for direct access within this 
         * chain.
         * 
         * In most cases, all authenticators and chains are assigned unique
         * keys so that this code snippet will give access to the only 
         * decorated authenticator object:
         * 
         * <code>
         * $object = $chain->authenticator($key)->current();
         * </code>
         * 
         * @param type $key
         * @return AuthenticatorBase|AuthenticatorFilterIterator
         */
        public function authenticator($key)
        {
                return self::rewind(
                        new AuthenticatorFilterIterator(
                        new ArrayKeyFilterIterator(
                        new RecursiveIteratorIterator(
                        new RecursiveArrayIterator($this->_chain), RecursiveIteratorIterator::SELF_FIRST
                        ), $key)
                ));
        }

        /**
         * Get iterator for all chains in this object.
         * @return AuthenticatorChain[]|ChainFilterIterator|array
         */
        public function chains()
        {
                return self::rewind(
                        new ChainFilterIterator(
                        new RecursiveIteratorIterator(
                        new RecursiveArrayIterator($this->_chain), RecursiveIteratorIterator::SELF_FIRST
                )));
        }

        /**
         * Get iterator all authenticators in this object.
         * @return AuthenticatorBase[] 
         */
        public function authenticators()
        {
                return self::rewind(
                        new AuthenticatorFilterIterator(
                        new RecursiveIteratorIterator(
                        new RecursiveArrayIterator($this->_chain), RecursiveIteratorIterator::SELF_FIRST
                )));
        }

        /**
         * Get array iterator.
         * @return RecursiveArrayIterator
         */
        public function getIterator()
        {
                return new RecursiveArrayIterator($this->_chain);
        }

        /**
         * Rewind and return iterator.
         * @param Iterator $iterator The iterator.
         * @return \Iterator
         */
        private static function rewind($iterator)
        {
                $iterator->rewind();
                return $iterator;
        }

}
