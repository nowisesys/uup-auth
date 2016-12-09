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
use UUP\Authentication\Stack\AuthenticatorChain;

/**
 * Filter on object instances of class AuthenticatorChain or array nodes.
 *
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class ChainFilterIterator extends FilterIterator
{

        /**
         * Check current iterator node.
         * 
         * Returns true if current iterator node is an instance of authenticator
         * chain or an array (possibly containing other authenticator chains). 
         * 
         * @return boolean
         */
        public function accept()
        {
                return $this->current() instanceof AuthenticatorChain || is_array($this->current());
        }

}
