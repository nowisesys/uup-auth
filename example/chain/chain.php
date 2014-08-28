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

// 
// Test driver for AuthenticatorChain class.
// 

if (!isset($_SERVER['argv'])) {
        die("This example should be runned from the command line\n.");
}

require_once __DIR__ . '/../../vendor/autoload.php';

use UUP\Authentication\Stack\AuthenticatorChain,
    UUP\Authentication\Authenticator\HostnameAuthenticator;

class ExampleChain extends AuthenticatorChain
{

        public function __toString()
        {
                return print_r($this, true);
        }

}

$chain = new ExampleChain();
printf("(i) construct(): %s\n", $chain);

$chain->add(
    'auth1', new HostnameAuthenticator()
);
printf("(i) add(): %s\n", $chain);

$chain->clear();
printf("(i) clear(): %s\n", $chain);

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
//     +-- chain2
//           +-- auth2
//           +-- auth5
//           +-- auth6
// 
$chain
    ->add('auth1', new HostnameAuthenticator('host1.example.com'))
    ->add('auth2', new HostnameAuthenticator('host2.example.com'))
    ->add('auth3', new HostnameAuthenticator('host3.example.com'))
    ->create('chain1')          // create and add to chain1
    ->add('auth4', new HostnameAuthenticator('host4.example.com'))
    ->create('chain2')          // create and add to chain2
    ->add('auth2', new HostnameAuthenticator('host2.example.com'))
    ->add('auth5', new HostnameAuthenticator('host5.example.com'))
    ->add('auth6', new HostnameAuthenticator('host6.example.com'))
;
// get and add to chain1
$chain->get('chain1')->add('auth7', new HostnameAuthenticator('host7.example.com'))
;
printf("(i) build: %s\n", $chain);

printf("(i) exist(): (chain1=%d, chain3=%d)\n", $chain->exist('chain1'), $chain->exist('chain3'));

printf("(i) iterator:\n");
foreach ($chain as $key => $obj) {
        printf("%s -> %s\n", $key, print_r($obj, true));
}

$chain->get('chain1')->remove('chain2');
printf("(i) remove(): %s\n", $chain);

$chain->want('chain3')->add('auth8', new HostnameAuthenticator('host8.example.com'));
$chain->want('chain3')->add('auth9', new HostnameAuthenticator('host9.example.com'));
printf("(i) want(): %s\n", $chain);
