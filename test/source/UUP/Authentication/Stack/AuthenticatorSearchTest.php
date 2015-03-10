<?php

namespace UUP\Authentication\Stack;

use ArrayIterator;
use UUP\Authentication\Authenticator\HostnameAuthenticator;
use UUP\Authentication\Stack\AuthenticatorFilter;
use UUP\Authentication\Stack\AuthenticatorSearch;
use UUP\Authentication\Stack\AuthenticatorTree;

require_once __DIR__ . '/AuthenticatorObjectTree.php';

/**
 * Generated by PHPUnit_SkeletonGenerator 1.2.1 on 2014-03-11 at 01:01:25.
 */
class AuthenticatorSearchTest extends \PHPUnit_Framework_TestCase
{

        /**
         * @var AuthenticatorFilter
         */
        protected $filter;

        public function __construct()
        {
                $this->filter = new AuthenticatorSearch((new AuthenticatorTree())->object);
        }

        /**
         * Sets up the fixture, for example, opens a network connection.
         * This method is called before a test is executed.
         */
        protected function setUp()
        {
                
        }

        /**
         * Tears down the fixture, for example, closes a network connection.
         * This method is called after a test is executed.
         */
        protected function tearDown()
        {
                
        }

        /**
         * @covers UUP\Authentication\Stack\AuthenticatorFilter::find
         */
        public function testFind()
        {
                $keys = array('auth2');
                foreach ($this->filter->find('auth2') as $key => $obj) {
                        printf("(i) authenticator(...): %s -> %s\n", $key, print_r($obj, true));
                        $this->assertTrue(in_array($key, $keys));
                        $this->assertTrue($obj instanceof HostnameAuthenticator);
                }

                foreach ($this->filter->find('auth10') as $key => $obj) {
                        printf("(i) authenticator(...): %s -> %s\n", $key, print_r($obj, true));
                        $this->fail();
                }
        }

        /**
         * @covers UUP\Authentication\Stack\AuthenticatorFilter::chain
         */
        public function testChain()
        {
                $keys = array('auth4', 'auth7', 'chain2');
                foreach ($this->filter->chain('chain1') as $chain) {
                        foreach ($chain as $key => $obj) {
                                printf("(i) chain(...): %s -> %s\n", $key, print_r($obj, true));
                                $this->assertTrue(in_array($key, $keys));
                                if ($key[0] == 'c') {
                                        $this->assertTrue(is_array($obj));
                                } else {
                                        $this->assertTrue($obj instanceof HostnameAuthenticator);
                                }
                        }
                }
                foreach ($this->filter->chain('chain4') as $key => $obj) {
                        printf("(i) chain(...): %s -> %s\n", $key, print_r($obj, true));
                        $this->fail();
                }
        }

        /**
         * @covers UUP\Authentication\Stack\AuthenticatorFilter::authenticator
         */
        public function testAuthenticator()
        {
                $keys = array('auth2');
                foreach ($this->filter->authenticator('auth2') as $key => $obj) {
                        printf("(i) authenticator(...): %s -> %s\n", $key, print_r($obj, true));
                        $this->assertTrue(in_array($key, $keys));
                        $this->assertTrue($obj instanceof HostnameAuthenticator);
                }

                foreach ($this->filter->authenticator('auth10') as $key => $obj) {
                        printf("(i) authenticator(...): %s -> %s\n", $key, print_r($obj, true));
                        $this->fail();
                }
        }

        /**
         * @covers UUP\Authentication\Stack\AuthenticatorFilter::chains
         */
        public function testChains()
        {
                $keys = array('chain1', 'chain2', 'chain3');
                foreach ($this->filter->chains() as $key => $obj) {
                        printf("(i) chains(): %s -> %s\n", $key, print_r($obj, true));
                        $this->assertTrue(in_array($key, $keys));
                        $this->assertTrue(is_array($obj));
                }
        }

        /**
         * @covers UUP\Authentication\Stack\AuthenticatorFilter::authenticators
         */
        public function testAuthenticators()
        {
                $keys = array('auth1', 'auth2', 'auth3', 'auth4', 'auth5', 'auth6', 'auth7', 'auth8', 'auth9');
                foreach ($this->filter->authenticators() as $key => $obj) {
                        printf("(i) authenticators(): %s -> %s\n", $key, print_r($obj, true));
                        $this->assertTrue(in_array($key, $keys));
                        $this->assertTrue($obj instanceof HostnameAuthenticator);
                }
        }

        /**
         * @covers UUP\Authentication\Stack\AuthenticatorFilter::getIterator
         */
        public function testGetIterator()
        {
                $this->assertNotNull($this->filter->getIterator());
                $this->assertTrue($this->filter->getIterator() instanceof ArrayIterator);
        }

}
