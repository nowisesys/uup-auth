<?php

/*
 * Copyright (C) 2014-2015 Anders Lövgren (Computing Department at BMC, Uppsala University).
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

// 
// Test driver for AuthenticatorSearch class (in depth authenticator and 
// chain filtering).
// 

if (!isset($_SERVER['argv'])) {
        die("This example should be runned from the command line\n.");
}

require_once __DIR__ . '/../../vendor/autoload.php';

use UUP\Authentication\Authenticator\HostnameAuthenticator;
use UUP\Authentication\Stack\AuthenticatorChain;
use UUP\Authentication\Stack\AuthenticatorSearch;

class ExampleChain extends AuthenticatorChain
{

        public function __toString()
        {
                return print_r($this, true);
        }

}

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
$chain = new ExampleChain();
$chain
    ->add('auth1', new HostnameAuthenticator('host1.example.com'))
    ->add('auth2', new HostnameAuthenticator('host2a.example.com'))
    ->add('auth3', new HostnameAuthenticator('host3.example.com'))
    ->create('chain1')          // create and add to chain1
    ->add('auth4', new HostnameAuthenticator('host4.example.com'))
    ->add('auth7', new HostnameAuthenticator('host7.example.com'))
    ->create('chain2')          // create and add to chain2
    ->add('auth2', new HostnameAuthenticator('host2b.example.com'))
    ->add('auth5', new HostnameAuthenticator('host5.example.com'))
    ->add('auth6', new HostnameAuthenticator('host6.example.com'))
;
$chain->create('chain3')
    ->add('auth8', new HostnameAuthenticator('host8.example.com'))
    ->add('auth9', new HostnameAuthenticator('host9.example.com'))
;
printf("chain: %s\n", $chain);
$filter = new AuthenticatorSearch($chain);

// chain1, chain2, chain3:
foreach ($filter->chains() as $key => $obj) {
        printf("(i) chains(): %s -> %s\n", $key, print_r($obj, true));
}

// auth4, auth7, chain2:
foreach ($filter->chain('chain1') as $key => $obj) {
        printf("(i) chain(...): %s -> %s\n", $key, print_r($obj, true));
}

// -- nothing --
foreach ($filter->chain('chain4') as $key => $obj) {
        printf("(i) chain(...): %s -> %s\n", $key, print_r($obj, true));
}

// -- all --
foreach ($filter->authenticators() as $key => $obj) {
        printf("(i) authenticators(): %s -> %s\n", $key, print_r($obj, true));
}

// auth2, auth2 (found in different chains):
foreach ($filter->authenticator('auth2') as $key => $obj) {
        printf("(i) authenticator(...): %s -> %s\n", $key, print_r($obj, true));
}

// auth4 (from chain1):
foreach ($filter->authenticator('auth4') as $key => $obj) {
        printf("(i) authenticator(...): %s -> %s\n", $key, print_r($obj, true));
}
