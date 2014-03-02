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

namespace UUP\Authentication;

use UUP\Authentication\Exception;

/**
 * Authenticator for IP-address. Authenticate caller by comparing the remote callers 
 * IP-address against the list if IP-address filters in this object. The remote caller 
 * is considered to be authenticated if one of the filter matches.
 * 
 * The IP-address argument (for constructor, add(), set() or remove()) can either be a single 
 * IP-address (string) or multiple IP-addresses using an array. The IP-address format
 * is either unique or an range: '192.168.1.1-192.168.1.129' or '192.168.1.0/24' (CIDR). 
 * An netmask can be used as an alternative to CIDR notation: '192.168.1.0/255.255.255.0'.
 * 
 * IPv6 is only supported using the single IP-address format, i.e. 'fe80::e1:5fff:fe90:6b0f'.
 * IP-addresses filter for localhost (IPv4 and IPv6) are always added. All addres filters,
 * including those for localhost can be removed by calling clear().
 * 
 * <code>
 * $reserved = new AddressAuthenticator('192.168.0.0/16');
 * $reserved->add(array('10.0.0.0/8', '172.16.0.0/12', '169.254.0.0/16');
 * if(!$reserved->authenticated()) {
 *      die("Sorry, only reserved IPv4 addresses are allowed to access this page!");
 * }
 * </code>
 * @property-read array $addresses The array of addresses.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class AddressAuthenticator implements Authenticator
{

        const localhost_ipv4 = '127.0.0.1';
        const localhost_ipv6 = '::1';
        const any_addr = '0.0.0.0/0';
        const any_mask = '255.255.255.255';

        private $address;

        /**
         * Constructor.
         * @param string|array $address IP-address.
         * @throws Exception
         */
        public function __construct($address = null)
        {
                $this->reset();
                $this->add($address);
        }

        public function __get($name)
        {
                if ($name == 'addresses') {
                        return $this->address;
                }
        }

        public function __toString()
        {
                return implode(",", $this->address);
        }

        /**
         * Set IP-address. Passing null to reset or an empty array to clear the address list.
         * @param string|array $address IP-address.
         * @throws Exception
         */
        public function set($address)
        {
                if (!isset($address)) {
                        $this->address = array();
                        $this->add(self::localhost_ipv4);
                        $this->add(self::localhost_ipv6);
                } elseif (is_string($address)) {
                        $this->address = array($address);
                } elseif (is_array($address)) {
                        $this->address = $address;
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
                        if (is_array($address)) {
                                $this->address = array_merge($this->address, $address);
                        } elseif (is_string($address)) {
                                $this->address[] = $address;
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
                                        if (($pos = array_search($addr, $this->address)) !== false) {
                                                unset($this->address[$pos]);
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
                return $this->address;
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
                        return in_array($address, $this->address);
                } elseif (is_array($address)) {
                        foreach ($address as $addr) {
                                if (!in_array($addr, $this->address)) {
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
                foreach ($this->address as $address) {
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

        public function authenticated()
        {
                return $this->match($_SERVER['REMOTE_ADDR']);
        }

        public function getUser()
        {
                return $_SERVER['REMOTE_ADDR'];
        }

        public function login()
        {
                // ignore
        }

        public function logout()
        {
                // ignore                
        }

        // 
        // Check a single IPv4 or IPv6 address.
        // 
        private static function checkSingle($address, $remote)
        {
                return $address == $remote;
        }

        private static function checkRange($address, $remote)
        {
                $a = new AddressProperties($address);
                $r = new AddressProperties($remote);

                self::output($a, "filter");
                self::output($r, "remote");

                return ($a->first <= $r->address) && ($r->address <= $a->last);
        }

        private static function checkMasked($address, $remote)
        {
                $a = new AddressProperties($address);
                $r = new AddressProperties($remote);

                self::output($a, "filter");
                self::output($r, "remote");

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

/**
 * Properties for an IPv4 address (single, range or masked). An address with
 * CIDR == 32 or netmask == 255.255.255.255 denotes a PTP-link. Such addresses
 * will not have an 
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
 */
class AddressProperties
{

        const any_mask = "255.255.255.255";
        const class_bits_mask = 0xF0000000;
        const class_a = 0x0;
        const class_b = 0x8;
        const class_c = 0xC;
        const class_d = 0xE;
        const class_e = 0xF;

        private $input;

        /**
         * Constructor.
         * @param string $address A single, range or masked IP-address.
         */
        public function __construct($address)
        {
                $this->input = $address;
                $this->decode($address);
        }

        public function __get($name)
        {
                if (isset($this->$name)) {
                        return $this->$name;
                }
        }

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

        // 
        // Decode an single address.
        // 
        private function single($addr)
        {
                $this->address = ip2long($addr);
                $this->cidr = 32;
                $this->hosts = 1;
                $this->class = ($this->address & self::class_bits_mask) >> 28;

                switch ($this->class) {
                        case self::class_a:     // Class A
                                $this->netmask = self::netmask(8);
                                break;
                        case self::class_b:     // Class B
                                $this->netmask = self::netmask(16);
                                break;
                        case self::class_c:     // Class C
                                $this->netmask = self::netmask(24);
                                break;
                        case self::class_d:     // Class D (multicast)
                                $this->netmask = ip2long(self::any_mask);
                                $this->first = ip2long('224.0.0.0');
                                $this->last = ip2long('239.255.255.255');
                                break;
                        case self::class_e:     // Class D (reserved)
                                $this->netmask = ip2long(self::any_mask);
                                $this->first = ip2long('240.0.0.0');
                                $this->last = ip2long('255.255.255.255');
                                break;
                        default:
                                throw new Exception(sprintf("Unknown address class %d", $this->class));
                }
                if ($this->class < self::class_d) {
                        $this->networking();
                }
        }

        // 
        // Decode an range of IP-addresses (xxx-xxx).
        // 
        private function range($addr)
        {
                $range = explode("-", $addr);

                $this->first = ip2long($range[0]);
                $this->last = ip2long($range[1]);

                $this->hosts = $this->last - $this->first;
        }

        // 
        // Decode an address having an address length (CIDR or netmask).
        // 
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

        // 
        // An helper function for setting network properties.
        // 
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

        // 
        // Netmask -> CIDR.
        // 
        private static function cidr($mask)
        {
                for ($mask = ((~$mask) & 0xffffffff), $cidr = 32; $mask != 0; --$cidr) {
                        $mask >>= 1;
                }
                return $cidr;
        }

        // 
        // CIDR -> netmask.
        // 
        private static function netmask($cidr)
        {
                if ($cidr == 0) {
                        return 0;
                }
                $mask = (int) ip2long(self::any_mask);
                $mask <<= (32 - $cidr);
                return $mask & 0xffffffff;
        }

}
