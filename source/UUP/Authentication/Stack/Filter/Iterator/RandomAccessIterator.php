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

namespace UUP\Authentication\Stack\Filter\Iterator;

use ArrayAccess;
use ArrayIterator;
use Iterator;
use IteratorAggregate;

/**
 * Random access iterator.
 * 
 * Creates a random access iterator from an ordinary iterator. The original
 * iterator (constructor argument) is not modified by this class. Notice
 * that this class don't preserve keys.
 *
 * @author Anders Lövgren (Nowise Systems/Uppsala University)
 * @package UUP
 * @subpackage Authentication
 */
class RandomAccessIterator implements ArrayAccess, IteratorAggregate
{

        /**
         * The data.
         * @var array 
         */
        private $_data = array();

        /**
         * Constructor.
         * @param Iterator $iterator The data iterator.
         */
        public function __construct(Iterator $iterator)
        {
                for ($iterator->rewind(); $iterator->valid(); $iterator->next()) {
                        $this->_data[$iterator->key()] = $iterator->current();
                }
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                $this->_data = null;
        }

        public function offsetExists($offset)
        {
                return isset($this->_data[$offset]);
        }

        public function offsetGet($offset)
        {
                return $this->_data[$offset];
        }

        public function offsetSet($offset, $value)
        {
                $this->_data[$offset] = $value;
        }

        public function offsetUnset($offset)
        {
                unset($this->_data[$offset]);
        }

        public function getIterator()
        {
                return new ArrayIterator($this->_data);
        }

}
