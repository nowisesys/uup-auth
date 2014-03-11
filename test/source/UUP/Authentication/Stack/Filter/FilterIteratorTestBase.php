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

use UUP\Authentication\Stack;

/**
 * Description of FilterIteratorBase
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 */
class FilterIteratorTestBase extends \PHPUnit_Framework_TestCase
{

        static $data;

        public function __construct()
        {
                self::$data = array(
                        "root" => array(
                                "decorator" => null,
                                "key3"      => "val3",
                                "key4"      => array(
                                        "key1" => "val4",
                                        "key5" => "val5",
                                        "key6" => array(
                                                "chain1" => new Stack\AuthenticatorChain()
                                        ),
                                ),
                                "key5"      => array(),
                                "key6"      => array("val6"),
                                "key7"      => 3,
                                "chain2"    => new Stack\AuthenticatorChain(),
                                "key1"      => ""
                        ),
                        "key8" => 4,
                        "key9" => array("key1" => 8)
                );
        }

}
