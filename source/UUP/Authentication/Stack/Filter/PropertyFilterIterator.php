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

namespace UUP\Authentication\Stack\Filter;

use Iterator;
use UUP\Authentication\Stack\Filter\PredicateFilterIterator;
use UUP\Authentication\Stack\Filter\PredicateFilterValidator;
use UUP\Authentication\Stack\Filter\PropertyFilterIterator;

/**
 * Filter iterator on object properties.
 *
 * @author Anders Lövgren (Nowise Systems/Uppsala University)
 * @package UUP
 * @subpackage Authentication
 */
class PropertyFilterIterator extends PredicateFilterIterator implements PredicateFilterValidator
{

        /**
         * The property name.
         * @var string 
         */
        private $_property;
        /**
         * The property value.
         * @var mixed 
         */
        private $_value;

        /**
         * Constructor.
         * @param Iterator $iterator The data iterator.
         * @param string $property The property name.
         * @param mixed $value The property value.
         */
        public function __construct(Iterator $iterator, $property, $value)
        {
                $this->_property = $property;
                $this->_value = $value;
                parent::__construct($iterator, $this);
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                parent::__destruct();

                $this->_property = null;
                $this->_value = null;
        }

        /**
         * Validate current iterator node.
         * 
         * @param Iterator $iterator The input iterator.
         * @return boolean
         */
        public function validate(Iterator $iterator)
        {
                return self::check($iterator->current(), $this->_property, $this->_value);
        }

        /**
         * Check if object property matches value.
         * 
         * @param object $obj The object with properties.
         * @param string $prop The property name.
         * @param mixed $value The property value.
         * @return boolean
         */
        protected static function check($obj, $prop, $value)
        {
                return $obj->$prop === $value;
        }

}

/**
 * Filter objects having the visible property equals to true.
 */
class VisibilityFilterIterator extends PropertyFilterIterator
{

        /**
         * constructor.
         * @param Iterator $iterator The data iterator.
         */
        public function __construct(Iterator $iterator)
        {
                parent::__construct($iterator, 'visible', true);
        }

}
