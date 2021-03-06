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

use ArrayIterator;
use IteratorAggregate;
use UUP\Authentication\Authenticator\Authenticator;
use UUP\Authentication\Stack\AuthenticatorChain;
use UUP\Authentication\Stack\AuthenticatorFilter;
use UUP\Authentication\Stack\AuthenticatorSearch;

/**
 * Chain of authenticators and sub chains.
 * 
 * This class represents a single authenticator chain that contains authenticator
 * objects, and possibly other authenticator sub chains if building hierarchic
 * trees of authenticator objects, see documentation for append.
 * 
 * This class provides access to and manipulation of authenticators and child 
 * chains that are immediate child objects in this chain using these member functions: 
 * insert(), get(), replace(), append(), remove() and exist().
 * 
 * See also AuthenticatorFilter and AuthenticatorSearch for filtering and 
 * traversal of the object hierarchy.
 * 
 * @author Anders Lövgren (Nowise Systems/Uppsala University)
 * @package UUP
 * @subpackage Authentication
 * 
 * @see AuthenticatorFilter
 * @see AuthenticatorSearch
 */
class AuthenticatorChain implements IteratorAggregate
{

        /**
         * The authenticator 
         * @var array
         */
        protected $_chain = array();

        /**
         * Constructor.
         * 
         * @param array $array The authenticator chains.
         * @see append
         */
        public function __construct($array = array())
        {
                $this->append($array);
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                $this->_chain = null;
        }

        /**
         * Insert authenticator or chain.
         * 
         * Add authenticator or authenticator chain (defined by object or array) 
         * as child object in this chain. Return reference to the inserted object.
         * 
         * @param string $key
         * @param Authenticator|AuthenticatorChain|array $object
         * @return Authenticator|AuthenticatorChain 
         * @see add()
         */
        public function insert($key, $object)
        {
                if (is_array($object)) {
                        $this->_chain[$key] = new self($object);
                } else {
                        $this->_chain[$key] = $object;
                }
                return $this->_chain[$key];
        }

        /**
         * Append array of authenticator and/or chains to this chain.
         * 
         * The argument should be an associative array of authenticator and/or chains,
         * possibly containing one or more sub arrays:
         * <code>
         * $chain->append(
         *      array(
         *              "auth1"  => ...,
         *              "auth2"  => ...,
         *                ...
         *              "chain1" => array(
         *                      "auth3"  => ...,
         *                      "chain2" => array(
         *                              "auth4" => ...,
         *                        ...
         *                      )
         *                        ...
         *              )
         *      )
         * );
         * </code>
         * Returns a reference to this chain.
         * @param array $array The authenticator chains.
         * @return AuthenticatorChain 
         */
        public function append($array)
        {
                foreach ($array as $key => $object) {
                        $this->insert($key, $object);
                }
                return $this;
        }

        /**
         * Remove named authenticator or chain from this chain.
         * @param string $key
         * @return AuthenticatorChain 
         */
        public function remove($key)
        {
                unset($this->_chain[$key]);
                return $this;
        }

        /**
         * Insert object in chain.
         * 
         * Returns reference to this chain.
         * @param string $key
         * @param Authenticator|AuthenticatorChain|array $object
         * @return AuthenticatorChain
         * @see insert()
         */
        public function add($key, $object)
        {
                $this->insert($key, $object);
                return $this;
        }

        /**
         * Create and return new empty chain.
         * @param string $key The chain key.
         * @return AuthenticatorChain
         */
        public function create($key)
        {
                return $this->insert($key, new self());
        }

        /**
         * Replace the array of authenticator and/or chains in this chain.
         * Returns a reference to this chain.
         * @param array $array See append().
         * @return AuthenticatorChain 
         * @see append()
         */
        public function replace($array)
        {
                $this->_chain = array();
                $this->append($array);
                return $this;
        }

        /**
         * Check if authenticator or chain exists in this chain.
         * @param string $key
         * @return bool
         */
        public function exist($key)
        {
                return isset($this->_chain[$key]);
        }

        /**
         * Return named authenticator or chain from this chain.
         * @param string $key
         * @return Authenticator|AuthenticatorChain
         */
        public function get($key)
        {
                return $this->_chain[$key];
        }

        /**
         * Alias for replace().
         * @param array $array See replace().
         * @see replace
         */
        public function set($array)
        {
                $this->replace($array);
        }

        /**
         * Clear this chain.
         */
        public function clear()
        {
                $this->replace(array());
        }

        /**
         * Get authenticator or chain from this chain. If key is missing in this
         * chain, then a new chain named by key is created and returned.
         * @param string $key
         * @return Authenticator|AuthenticatorChain
         */
        public function want($key)
        {
                return isset($this->_chain[$key]) ? $this->_chain[$key] : $this->create($key);
        }

        /**
         * Get array iterator.
         * @return ArrayIterator
         */
        public function getIterator()
        {
                return new ArrayIterator($this->_chain);
        }

        /**
         * Get chains array.
         * @return array
         */
        public function getArrayCopy()
        {
                return $this->_chain;
        }

}
