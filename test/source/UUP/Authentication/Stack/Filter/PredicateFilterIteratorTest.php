<?php

namespace UUP\Authentication\Stack\Filter;

require_once 'FilterIteratorTestBase.php';

use UUP\Authentication\Stack\Filter\PredicateFilterValidator;

/**
 * Generated by PHPUnit_SkeletonGenerator 1.2.1 on 2014-03-06 at 00:21:56.
 */
class PredicateFilterIteratorTest extends FilterIteratorTestBase implements PredicateFilterValidator
{

        /**
         * @var PredicateFilterIterator
         */
        protected $object;
        private $validate;

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
         * @covers UUP\Authentication\Stack\Filter\PredicateFilterIterator::accept
         */
        public function testAccept()
        {
                $iterator = new \RecursiveArrayIterator(array());
                $this->object = new PredicateFilterIterator($iterator, $this);
                $this->validate = true;
                $this->assertTrue($this->object->accept());
                $this->validate = false;
                $this->assertFalse($this->object->accept());

                // 
                // $this->object->accept() returns true if current node has children!
                // 
                $iterator = new \RecursiveArrayIterator(self::$data);
                $this->object = new PredicateFilterIterator($iterator, $this);
                $this->validate = true;
                $this->assertTrue($this->object->accept());
                $this->validate = false;
                $this->assertFalse($this->object->accept());
        }

        public function validate(\Iterator $iterator)
        {
                return $this->validate;
        }

}