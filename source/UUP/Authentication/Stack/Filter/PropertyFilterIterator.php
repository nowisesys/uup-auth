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

namespace UUP\Authentication\Stack\Filter;

/**
 * Filter iterator on object properties.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class PropertyFilterIterator extends PredicateFilterIterator implements PredicateFilterValidator
{

        private $property;
        private $value;

        public function __construct(\Iterator $iterator, $property, $value)
        {
                $this->property = $property;
                $this->value = $value;
                parent::__construct($iterator, $this);
        }

        public function validate(\Iterator $iterator)
        {
                return self::check($iterator->current(), $this->property, $this->value);
        }

        protected static function check($obj, $prop, $value)
        {
                // return (isset($obj->$prop) && ($obj->$prop === $value));
                return $obj->$prop === $value;
        }

}

/**
 * Filter objects having the visible property equals to true.
 */
class VisibilityFilterIterator extends PropertyFilterIterator
{

        public function __construct(\Iterator $iterator)
        {
                parent::__construct($iterator, 'visible', true);
        }

}
