<?php

/*
 * Copyright (C) 2014-2016 Anders Lövgren (Computing Department at BMC, Uppsala University).
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

namespace UUP\Authentication\Stack\Filter;

use FilterIterator;
use Iterator;

/**
 * Filter on array keys matching the supplied name.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class ArrayKeyFilterIterator extends FilterIterator
{

        /**
         * The key name.
         * @var string 
         */
        private $_name;

        /**
         * Constructor.
         * @param Iterator $iterator The data iterator.
         * @param string $key The key name.
         */
        public function __construct(Iterator $iterator, $key)
        {
                $this->_name = $key;
                parent::__construct($iterator);
        }
        
        /**
         * Destructor.
         */
        public function __destruct()
        {
                $this->_name = null;
        }

        /**
         * Check current iterator node.
         * 
         * Returns true if key of current iterator node matches the key
         * name of this object.
         * 
         * @return boolean
         */
        public function accept()
        {
                return $this->key() === $this->_name;
        }

}
