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

use UUP\Authentication\HostnameAuthenticator;

class AuthenticatorTree
{

        public $object;

        public function __construct()
        {
                // 
                // Build tree of chains:
                // 
                //   chain
                //     +-- auth1
                //     +-- auth2
                //     +-- auth3
                //     +-- chain1
                //     |     +-- auth4
                //     |     +-- auth7
                //     |     +-- chain2
                //     |           +-- auth2
                //     |           +-- auth5
                //     |           +-- auth6
                //     +-- chain3
                //           +-- auth8
                //           +-- auth9
                // 
                $this->object = new AuthenticatorChain();
                $this->object
                    ->add('auth1', new HostnameAuthenticator('host1.example.com'))
                    ->add('auth2', new HostnameAuthenticator('host2.example.com'))
                    ->add('auth3', new HostnameAuthenticator('host3.example.com'))
                    ->create('chain1')          // create and add to chain1
                    ->add('auth4', new HostnameAuthenticator('host4.example.com'))
                    ->add('auth7', new HostnameAuthenticator('host7.example.com'))
                    ->create('chain2')          // create and add to chain2
                    ->add('auth2', new HostnameAuthenticator('host2.example.com'))
                    ->add('auth5', new HostnameAuthenticator('host5.example.com'))
                    ->add('auth6', new HostnameAuthenticator('host6.example.com'))
                ;
                $this->object->create('chain3')
                    ->add('auth8', new HostnameAuthenticator('host8.example.com'))
                    ->add('auth9', new HostnameAuthenticator('host9.example.com'))
                ;
        }

}
