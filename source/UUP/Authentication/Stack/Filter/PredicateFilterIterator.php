<?php

/*
 * Copyright (C) 2014-2016 Anders Lövgren (QNET/BMC CompDept).
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
use UUP\Authentication\Stack\Filter\PredicateFilterValidator;

/**
 * Interface for predicate based iterator filtering. 
 * 
 * Classes that implements this interface can be used as functional objects
 * for predicate filtering.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
interface PredicateFilterValidator
{

        /**
         * Validate current iterator node.
         * 
         * @param Iterator $iterator The input iterator.
         * @return boolean
         */
        function validate(Iterator $iterator);
}

/**
 * Filter array based on keys matching the predicate.
 * 
 * Example of class property filtering. The class VisibilityFilterIterator
 * filter all objects having the visibility property set to true.
 * <code>
 * class PropertyFilterIterator extends PredicateFilterIterator implements PredicateFilterValidator
 * {
 *       private $property;
 *       private $value;
 *
 *       public function __construct(\Iterator $iterator, $property, $value)
 *       {
 *               $this->property = $property;
 *               $this->value = $value;
 *               parent::__construct($iterator, $this);
 *       }
 *
 *       public function validate(\Iterator $iterator)
 *       {
 *               return self::check($iterator->current(), $this->property, $this->value);
 *       }
 * 
 *       protected static function check($obj, $prop, $value) 
 *       {
 *               return isset($obj->$prop) && ($obj->$prop == $value);
 *       }
 * }
 * 
 * class VisibilityFilterIterator extends PropertyFilterIterator
 * {
 *       public function __construct(\Iterator $iterator)
 *       {
 *               parent::__construct($iterator, 'visibility', true);
 *       }
 * }
 * </code>
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class PredicateFilterIterator extends FilterIterator
{

        /**
         * The predicate object.
         * @var PredicateFilterValidator 
         */
        private $_predicate;

        /**
         * 
         * @param Iterator $iterator The data iterator.
         * @param PredicateFilterValidator $predicate The predicate object.
         */
        public function __construct(Iterator $iterator, PredicateFilterValidator $predicate)
        {
                $this->_predicate = $predicate;
                parent::__construct($iterator);
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                $this->_predicate = null;
        }

        /**
         * Check this object using predicate validation.
         * @return boolean
         */
        public function accept()
        {
                return $this->_predicate->validate($this);
        }

}
