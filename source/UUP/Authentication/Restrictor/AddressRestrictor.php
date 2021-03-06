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

namespace UUP\Authentication\Restrictor {

        use UUP\Authentication\Authenticator\Authenticator;
        use UUP\Authentication\Exception;
        use UUP\Authentication\Library\Authenticator\AddressProperties;
        use UUP\Authentication\Library\Authenticator\AuthenticatorBase;

        /**
         * IP-address restriction. 
         * 
         * Authorize caller by comparing the remote callers IP-address against the 
         * list if IP-address filters in this object. The remote caller is considered 
         * to be authorized if one of the filter matches.
         * 
         * The IP-address argument (for constructor, add(), set() or remove()) can either
         * be a single IP-address (string) or multiple IP-addresses using an array. 
         * The IP-address format is either unique or an range: '192.168.1.1-192.168.1.129' 
         * or '192.168.1.0/24' (CIDR). An netmask can be used as an alternative to 
         * CIDR notation: '192.168.1.0/255.255.255.0'.
         * 
         * IPv6 is only supported using the single IP-address format, i.e. 'fe80::e1:5fff:fe90:6b0f'.
         * IP-addresses filter for localhost (IPv4 and IPv6) are always added. All addres 
         * filters, including those for localhost can be removed by calling clear().
         * 
         * <code>
         * $reserved = new AddressRestrictor('192.168.0.0/16');
         * $reserved->add(array('10.0.0.0/8', '172.16.0.0/12', '169.254.0.0/16');
         * if(!$reserved->accepted()) {
         *      die("Sorry, only reserved IPv4 addresses are allowed to access this page!");
         * }
         * </code>
         * @property-read array $addresses The array of addresses.
         * 
         * @author Anders Lövgren (Nowise Systems/Uppsala University)
         * @package UUP
         * @subpackage Authentication
         */
        class AddressRestrictor extends AuthenticatorBase implements Restrictor
        {

                /**
                 * The IPv4 address for localhost.
                 */
                const LOCALHOST_IPV4 = '127.0.0.1';
                /**
                 * The IPv6 address for localhost.
                 */
                const LOCALHOST_IPV6 = '::1';
                /**
                 * The IPv4 any address.
                 */
                const ANY_ADDR = '0.0.0.0/0';
                /**
                 * The IPv4 any subnet mask.
                 */
                const ANY_MASK = '255.255.255.255';
                /**
                 * The address range delimiter.
                 */
                const DELIMITER = ";";

                /**
                 * The IP-addresses.
                 * @var array
                 */
                private $_address;

                /**
                 * Constructor.
                 * @param string|array $address IP-address.
                 * @throws Exception
                 */
                public function __construct($address = null)
                {
                        parent::__construct();

                        $this->reset();
                        $this->add($address);
                        $this->visible(false);
                        $this->control(Authenticator::REQUIRED);
                }

                /**
                 * Destructor.
                 */
                public function __destruct()
                {
                        parent::__destruct();
                        $this->_address = null;
                }

                public function __get($name)
                {
                        if ($name == 'addresses') {
                                return $this->_address;
                        } else {
                                return parent::__get($name);
                        }
                }

                public function __toString()
                {
                        return implode(self::DELIMITER, $this->_address);
                }

                /**
                 * Set IP-address. Passing null to reset or an empty array to clear the address list.
                 * @param string|array $address IP-address.
                 * @throws Exception
                 */
                public function set($address)
                {
                        if (!isset($address)) {
                                $this->_address = array();
                                $this->add(self::LOCALHOST_IPV4);
                                $this->add(self::LOCALHOST_IPV6);
                        } elseif (is_string($address) && strpos($address, self::DELIMITER)) {
                                $this->_address = explode(self::DELIMITER, $address);
                        } elseif (is_string($address)) {
                                $this->_address = array($address);
                        } elseif (is_array($address)) {
                                $this->_address = $address;
                        } else {
                                throw new Exception('Invalid argument type');
                        }
                }

                /**
                 * Reset address list to initial state. Alias for set(null).
                 */
                public function reset()
                {
                        $this->set(null);
                }

                /**
                 * Clear the address list. Alias for set(array()).
                 */
                public function clear()
                {
                        $this->set(array());
                }

                /**
                 * Add IP-address to filter.
                 * @param string|array $address IP-address.
                 * @throws Exception
                 */
                public function add($address)
                {
                        if (isset($address)) {
                                if (is_string($address) && strpos($address, self::DELIMITER)) {
                                        $address = explode(self::DELIMITER, $address);
                                }
                                if (is_array($address)) {
                                        $this->_address = array_merge($this->_address, $address);
                                        $this->_address = array_unique($this->_address);
                                } elseif (is_string($address)) {
                                        $this->_address[] = $address;
                                } else {
                                        throw new Exception('Invalid argument type');
                                }
                        }
                }

                /**
                 * Remove IP-address from filter.
                 * @param string|array $address IP-address.
                 * @throws Exception
                 */
                public function remove($address)
                {
                        if (isset($address)) {
                                if (is_string($address)) {
                                        $address = array($address);
                                }
                                if (is_array($address)) {
                                        foreach ($address as $addr) {
                                                if (($pos = array_search($addr, $this->_address)) !== false) {
                                                        unset($this->_address[$pos]);
                                                }
                                        }
                                } else {
                                        throw new Exception('Invalid argument type');
                                }
                        }
                }

                /**
                 * Return array of IP-addresses.
                 * @return array
                 */
                public function get()
                {
                        return $this->_address;
                }

                /**
                 * Check if addresses contains the address. If the $address argument is an 
                 * array, the all elements must be in this objects address list.
                 * 
                 * @param string|array $address The address to check.
                 * @return bool
                 * @throws Exception
                 */
                public function contains($address)
                {
                        if (is_string($address)) {
                                return in_array($address, $this->_address);
                        } elseif (is_array($address)) {
                                foreach ($address as $addr) {
                                        if (!in_array($addr, $this->_address)) {
                                                return false;
                                        }
                                }
                                return true;
                        } else {
                                throw new Exception('Invalid argument type');
                        }
                }

                /**
                 * Check whether the remote IP-address is matched by this objects address list.
                 * @param string $remote The remote IP-adress.
                 * @return boolean
                 */
                public function match($remote)
                {
                        foreach ($this->_address as $address) {
                                if (strstr($address, ':')) {
                                        if (self::checkSingle($address, $remote)) {
                                                return true;
                                        }
                                } elseif (strstr($address, '-')) {
                                        if (self::checkRange($address, $remote)) {
                                                return true;
                                        }
                                } elseif (strstr($address, '/')) {
                                        if (self::checkMasked($address, $remote)) {
                                                return true;
                                        }
                                } else {
                                        if (self::checkSingle($address, $remote)) {
                                                return true;
                                        }
                                }
                        }
                        return false;
                }

                /**
                 * Check if peer address is accepted.
                 * @return boolean
                 */
                public function accepted()
                {
                        return $this->match($this->getSubject());
                }

                /**
                 * Get peer address.
                 * @return string
                 */
                public function getSubject()
                {
                        return $_SERVER['REMOTE_ADDR'];
                }

                /**
                 * Check single IP address.
                 * 
                 * @param string $address The accepted address.
                 * @param string $remote The address to check.
                 * @return boolean
                 */
                private static function checkSingle($address, $remote)
                {
                        return $address == $remote;
                }

                /**
                 * Check range of IP addresses.
                 * 
                 * This function checks if a single address or network (in remote) is
                 * contained in the address range (the address argument).
                 * 
                 * @param string $address The address range.
                 * @param string $remote The remote address.
                 * @return boolean
                 */
                private static function checkRange($address, $remote)
                {
                        $a = new AddressProperties($address);
                        $r = new AddressProperties($remote);

                        return ($a->first <= $r->address) && ($r->address <= $a->last);
                }

                /**
                 * Check if IP address is masked.
                 * 
                 * This function checks if a single address or network (in remote) is
                 * masked by the address range (the address argument).
                 * 
                 * @param string $address The address range.
                 * @param string $remote The remote address.
                 * @return boolean
                 */
                private static function checkMasked($address, $remote)
                {
                        $a = new AddressProperties($address);
                        $r = new AddressProperties($remote);

                        if ($a->address == 0 && $a->netmask == 0) {
                                return true;    // '0.0.0.0/0' => match all
                        }

                        if ($a->hosts == 1) {
                                return $a->address == $r->address;
                        } else {
                                return ($a->network <= $r->address) && ($r->address <= $a->broadcast);
                        }
                }

                /**
                 * Display IP-address properties.
                 * @param string $addr The IP-address. 
                 * @param string $text Optional label text.
                 */
                public static function output($addr, $text = null)
                {
                        if (is_string($addr)) {
                                $addr = new AddressProperties($addr);
                        }

                        if (isset($text)) {
                                printf("** %s (%s)\n", $text, $addr->input);
                        }
                        printf("address:   %20s (%032b)\n", long2ip($addr->address), $addr->address);
                        printf("netmask:   %20s (%032b)\n", long2ip($addr->netmask), $addr->netmask);
                        printf("network:   %20s (%032b)\n", long2ip($addr->network), $addr->network);
                        printf("broadcast: %20s (%032b)\n", long2ip($addr->broadcast), $addr->broadcast);
                        printf("first:     %20s (%032b)\n", long2ip($addr->first), $addr->first);
                        printf("last:      %20s (%032b)\n", long2ip($addr->last), $addr->last);
                        printf("hosts:     %20d (/%s)\n", $addr->hosts, $addr->cidr);
                }

        }

}

namespace UUP\Authentication\Library\Authenticator {

        use UUP\Authentication\Exception;

        /**
         * Properties for an IPv4 address (single, range or masked). 
         * 
         * An address with CIDR == 32 or netmask == 255.255.255.255 denotes a PTP-link. 
         * Such addresses will not have network or broadcast addresses assigned to them.
         * 
         * @property-read long $address The IP-address.
         * @property-read long $network The network address.
         * @property-read long $netmask The network mask.
         * @property-read long $gateway Assuming gateway is network + 1.
         * @property-read long $broadcast The broadcast address.
         * @property-read long $first The first IP-address on this network.
         * @property-read long $last The last IP-address on this network.
         * @property-read int $cidr The CIDR address mask.
         * @property-read int $hosts The number of hosts on this network.
         * @property-read string $input The input argument for constructor.
         * 
         * @author Anders Lövgren (Nowise Systems/Uppsala University)
         * @package UUP
         * @subpackage Authentication
         */
        class AddressProperties
        {

                /**
                 * The any address mask.
                 */
                const ANY_MASK = "255.255.255.255";
                /**
                 * The address class bit mask.
                 */
                const CLASS_BITS_MASK = 0xF0000000;
                /**
                 * The class A network bits.
                 */
                const CLASS_A_BITS = 0x0;
                /**
                 * The class B network bits.
                 */
                const CLASS_B_BITS = 0x8;
                /**
                 * The class C network bits.
                 */
                const CLASS_C_BITS = 0xC;
                /**
                 * The class D network bits.
                 */
                const CLASS_D_BITS = 0xE;
                /**
                 * The class E network bits.
                 */
                const CLASS_E_BITS = 0xF;
                /**
                 * The class A network mask.
                 */
                const CLASS_A_MASK = 0x8;
                /**
                 * The class B network mask.
                 */
                const CLASS_B_MASK = 0xC;
                /**
                 * The class C network mask.
                 */
                const CLASS_C_MASK = 0xE;
                /**
                 * The class D network mask.
                 */
                const CLASS_D_MASK = 0xF;
                /**
                 * The class E network mask.
                 */
                const CLASS_E_MASK = 0xF;

                /**
                 * The input address.
                 * @var string 
                 */
                private $_input;

                /**
                 * Constructor.
                 * @param string $address A single address, an IP address range or masked IP-address (addr/mask).
                 */
                public function __construct($address)
                {
                        $this->_input = $address;
                        $this->decode($address);
                }

                /**
                 * Destructor.
                 */
                public function __destruct()
                {
                        $this->_input = null;
                }

                public function __get($name)
                {
                        if (isset($this->$name)) {
                                return $this->$name;
                        }
                }

                /**
                 * Decode an address.
                 * 
                 * The input argument is either addr (single adress), addr1-addr2 (an 
                 * range of addresses) or addr/mask (an masked address).
                 * 
                 * @param string $addr The input address.
                 */
                private function decode($addr)
                {
                        if (strstr($addr, "-")) {
                                $this->range($addr);
                        } elseif (strstr($addr, "/")) {
                                $this->masked($addr);
                        } else {
                                $this->single($addr);
                        }
                }

                /**
                 * Decode single address.
                 * @param string $addr The input address.
                 * @throws Exception
                 */
                private function single($addr)
                {
                        $this->address = ip2long($addr);
                        $this->cidr = 32;
                        $this->hosts = 1;
                        $this->class = ($this->address & self::CLASS_BITS_MASK) >> 28;  // Leading four bits

                        if (($this->class & self::CLASS_A_MASK) == self::CLASS_A_BITS) {
                                $this->class = 'A';
                        } elseif (($this->class & self::CLASS_B_MASK) == self::CLASS_B_BITS) {
                                $this->class = 'B';
                        } elseif (($this->class & self::CLASS_C_MASK) == self::CLASS_C_BITS) {
                                $this->class = 'C';
                        } elseif (($this->class & self::CLASS_D_MASK) == self::CLASS_D_BITS) {
                                $this->class = 'D';
                        } elseif (($this->class & self::CLASS_E_MASK) == self::CLASS_E_BITS) {
                                $this->class = 'E';
                        }

                        switch ($this->class) {
                                case 'A':       // Class A
                                        $this->netmask = self::netmask(8);
                                        break;
                                case 'B':       // Class B
                                        $this->netmask = self::netmask(16);
                                        break;
                                case 'C':       // Class C
                                        $this->netmask = self::netmask(24);
                                        break;
                                case 'D':       // Class D (multicast)
                                        $this->netmask = ip2long(self::ANY_MASK);
                                        $this->first = ip2long('224.0.0.0');
                                        $this->last = ip2long('239.255.255.255');
                                        break;
                                case 'E':       // Class E (reserved)
                                        $this->netmask = ip2long(self::ANY_MASK);
                                        $this->first = ip2long('240.0.0.0');
                                        $this->last = ip2long('255.255.255.255');
                                        break;
                                default:
                                        throw new Exception(sprintf("Unknown address class 0x%X", $this->class));
                        }
                        if ($this->class != 'D' && $this->class != 'E') {
                                $this->networking();
                        }
                }

                /**
                 * Decode address range (xxx-xxx).
                 * @param string $addr The input address.
                 */
                private function range($addr)
                {
                        $range = explode("-", $addr);

                        $this->first = ip2long($range[0]);
                        $this->last = ip2long($range[1]);

                        $this->hosts = $this->last - $this->first;
                }

                /**
                 * Decode masked address (CIDR or netmask notation).
                 * @param type $addr The input address.
                 */
                private function masked($addr)
                {
                        $part = explode("/", $addr);

                        $addr = $part[0];
                        $mask = $part[1];

                        if (strstr($mask, ".")) {
                                $this->netmask = ip2long($mask);
                                $this->cidr = self::cidr($this->netmask);
                        } else {
                                $this->netmask = self::netmask($mask);
                                $this->cidr = $mask;
                        }

                        $this->address = ip2long($addr);
                        $this->networking();
                }

                /**
                 * Set network properties.
                 * 
                 * This is purily an helper method for detecting network, broadcast,
                 * gateway, first and last address and number of hosts.
                 */
                private function networking()
                {
                        $this->network = $this->address & $this->netmask;
                        $this->broadcast = $this->address | ((~$this->netmask) & 0xffffffff);

                        if ($this->network == $this->broadcast) {
                                unset($this->network);
                                unset($this->broadcast);
                        } else {
                                $this->gateway = $this->network + 1;
                                $this->first = $this->network + 1;
                                $this->last = $this->broadcast - 1;
                        }

                        if ($this->first == $this->last) {
                                $this->hosts = 1;       // PTP link
                        } elseif ($this->last - $this->first < 0) {
                                $this->hosts = 0;
                                unset($this->first);
                                unset($this->last);
                        } else {
                                $this->hosts = $this->last - $this->first;
                        }
                }

                /**
                 * Subnet mask converter (netmask -> CIDR).
                 * 
                 * Returns the CIDR length given an standard subnet mask.
                 * @param int $mask The subnet mask.
                 * @return int
                 */
                private static function cidr($mask)
                {
                        for ($mask = ((~$mask) & 0xffffffff), $cidr = 32; $mask != 0; --$cidr) {
                                $mask >>= 1;
                        }
                        return $cidr;
                }

                /**
                 * Subnet mask converter (CIDR -> netmask).
                 * 
                 * Returns the standard subnet mask given an CIDR length.
                 * @param int $cidr The CIDR length.
                 * @return int
                 */
                private static function netmask($cidr)
                {
                        if ($cidr == 0) {
                                return 0;
                        }
                        $mask = (int) ip2long(self::ANY_MASK);
                        $mask <<= (32 - $cidr);
                        return $mask & 0xffffffff;
                }

        }

}
