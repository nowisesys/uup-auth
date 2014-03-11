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

namespace UUP\Authentication\Stack;

use UUP\Authentication\Stack\AuthenticatorFilter;

/**
 * Authenticator object and chain search class.
 * 
 * These functions works in depth on this chain, including any child chains, 
 * and returns an iterator for traversing the result: find(), chain(), chains(),
 * authenticator() and authenticators(). 
 * 
 * Wrap the returned iterator in an RandomAccessIterator for array like access
 * to filtered result members.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class AuthenticatorSearch extends AuthenticatorFilter
{

        /**
         * Constructor.
         * @param AuthenticatorChain
         * @throws Exception
         */
        public function __construct($chain)
        {
                if (!extension_loaded('SPL')) {
                        throw new Exception('The SPL extension is not loaded');
                }
                parent::__construct(self::transform($chain));
        }

        /**
         * Transform this and any sub AuthenticatorChain objects to array.
         * @param AuthenticatorChain $chain
         * @return array 
         */
        private static function transform($chain, $array = array())
        {
                foreach ($chain as $key => $obj) {
                        if ($obj instanceof AuthenticatorChain) {
                                $array[$key] = self::transform($obj);
                        } else {
                                $array[$key] = $obj;
                        }
                }
                return $array;
        }

}
