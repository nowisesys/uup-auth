<?php

/*
 * Copyright (C) 2014 Anders Lövgren (QNET/BMC CompDept).
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

/**
 * Random access iterator.
 * 
 * Creates a random access iterator from an ordinary iterator. The original
 * iterator (constructor argument) is not modified by this class. Notice
 * that this class don't preserve keys.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class RandomAccessIterator implements \ArrayAccess, \IteratorAggregate
{

        private $data = array();

        public function __construct(\Iterator $iterator)
        {
                for ($iterator->rewind(); $iterator->valid(); $iterator->next()) {
                        $this->data[$iterator->key()] = $iterator->current();
                }
        }

        public function offsetExists($offset)
        {
                return isset($this->data[$offset]);
        }

        public function offsetGet($offset)
        {
                return $this->data[$offset];
        }

        public function offsetSet($offset, $value)
        {
                $this->data[$offset] = $value;
        }

        public function offsetUnset($offset)
        {
                unset($this->data[$offset]);
        }

        public function getIterator()
        {
                return new \ArrayIterator($this->data);
        }

}
