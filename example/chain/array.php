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

// 
// Test driver for ChainArrayAccess class.
// 

if (!isset($_SERVER['argv'])) {
        die("This example should be runned from the command line\n.");
}

require_once __DIR__ . '/../../vendor/autoload.php';

use UUP\Authentication\Stack\AuthenticatorChain,
    UUP\Authentication\Stack\Access\ChainArrayAccess,
    UUP\Authentication\Authenticator\HostnameAuthenticator;

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

// Create the real chain object:
$chain = new ExampleChain();

// Create array access wrapper:
$array = new ChainArrayAccess($chain);

// Insert authenticator objects. Chains will be dynamic created:
$array['auth1'] = new HostnameAuthenticator('host1.example.com');
$array['auth2'] = new HostnameAuthenticator('host2.example.com');
$array['auth3'] = new HostnameAuthenticator('host3.example.com');
$array['chain1']['auth4'] = new HostnameAuthenticator('host4.example.com');
$array['chain1']['auth7'] = new HostnameAuthenticator('host7.example.com');
$array['chain1']['chain2']['auth2'] = new HostnameAuthenticator('host2.example.com');
$array['chain1']['chain2']['auth5'] = new HostnameAuthenticator('host5.example.com');
$array['chain1']['chain2']['auth6'] = new HostnameAuthenticator('host6.example.com');
$array['chain3']['auth8'] = new HostnameAuthenticator('host8.example.com');
$array['chain3']['auth9'] = new HostnameAuthenticator('host9.example.com');

printf("chain: %s\n", $chain);
