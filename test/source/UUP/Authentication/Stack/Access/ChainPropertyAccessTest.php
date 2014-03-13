<?php

namespace UUP\Authentication\Stack\Access;

use UUP\Authentication\Stack\AuthenticatorChain;

require_once __DIR__ . '/ChainAccessObject.php';

/**
 * Generated by PHPUnit_SkeletonGenerator 1.2.1 on 2014-03-13 at 02:00:15.
 */
class ChainPropertyAccessTest extends \PHPUnit_Framework_TestCase
{

        /**
         * @var ChainArrayAccess
         */
        protected $chain;
        /**
         * @var ChainAccessObject
         */
        protected $object;

        /**
         * Sets up the fixture, for example, opens a network connection.
         * This method is called before a test is executed.
         */
        protected function setUp()
        {
                $this->object = new ChainAccessObject();
                $this->chain = new ChainPropertyAccess(
                    new AuthenticatorChain(array('obj1' => $this->object)
                ));
        }

        /**
         * Tears down the fixture, for example, closes a network connection.
         * This method is called after a test is executed.
         */
        protected function tearDown()
        {
                
        }

        /**
         * @covers UUP\Authentication\Stack\Access\ChainPropertyAccess::__get
         */
        public function test__get()
        {
                $this->assertNotNull($this->chain->obj1);
                $this->assertNotNull($this->chain->obj2);     // created "on demand"
                $this->assertNotNull($this->chain->obj2->sub);

                $this->assertTrue($this->chain->obj1 instanceof ChainPropertyAccess);
                $this->assertTrue($this->chain->obj2 instanceof ChainPropertyAccess);
        }

        /**
         * @covers UUP\Authentication\Stack\Access\ChainPropertyAccess::__set
         */
        public function test__set()
        {
                $this->chain->obj1->prop = 3;       // use property
                $this->assertTrue($this->chain->obj1->prop == $this->object->prop);
                $this->chain->obj1->func = 2;       // use function
                $this->assertTrue($this->chain->obj1->func == $this->object->func);
                $this->chain->obj1->name = "xxx";   // throws

                $this->chain->obj2 = new ChainAccessObject();
                $this->chain->obj2->prop = 5;
                $this->assertTrue($this->chain->obj2->prop == 5);
                $this->assertTrue($this->chain->obj1->prop == $this->object->prop);
        }

        /**
         * @covers UUP\Authentication\Stack\Access\ChainPropertyAccess::__isset
         */
        public function test__isset()
        {
                $this->assertTrue(isset($this->chain->obj1));
                $this->assertFalse(isset($this->chain->obj2));
        }

        /**
         * @covers UUP\Authentication\Stack\Access\ChainPropertyAccess::__unset
         */
        public function test__unset()
        {
                $this->assertTrue(isset($this->chain->obj1));
                unset($this->chain->obj1);
                $this->assertFalse(isset($this->chain->obj1));
        }

}