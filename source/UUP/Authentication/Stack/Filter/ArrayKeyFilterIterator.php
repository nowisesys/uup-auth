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

namespace UUP\Authentication\Stack\Filter;

/**
 * Filter on array keys matching the supplied name.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class ArrayKeyFilterIterator extends \FilterIterator
{

        private $name;

        public function __construct(\Iterator $iterator, $key)
        {
                $this->name = $key;
                parent::__construct($iterator);
        }

        public function accept()
        {
                return $this->key() === $this->name;
        }

}