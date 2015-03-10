<?php

namespace UUP\Authentication\Stack\Filter;

use RecursiveArrayIterator;
use RecursiveIteratorIterator;
use UUP\Authentication\Stack\Filter\ArrayKeyFilterIterator;
use UUP\Authentication\Stack\Filter\FilterIteratorTestBase;

require_once 'FilterIteratorTestBase.php';

class ArrayKeyFilterIteratorTest extends FilterIteratorTestBase
{

        /**
         * @var KeyFilterIterator
         */
        protected $object;

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
         * @covers UUP\Authentication\Stack\Filter\ArrayKeyFilterIterator::accept
         */
        public function testAccept()
        {

                // 
                // Testing accept() direct is pointless. We must create a new iterator
                // for $this->object (using RecursiveIteratorIterator) to get the actual
                // result.
                // 

                $this->check('root');
                $this->check('decorator');
                $this->check('key3');
                $this->check('key5');
                $this->check('key7');
        }

        /**
         * @group ignore
         */
        private function check($name)
        {
                $iterator = new RecursiveArrayIterator(array());
                $this->object = new RecursiveIteratorIterator($iterator, RecursiveIteratorIterator::CHILD_FIRST);
                $this->result = new ArrayKeyFilterIterator($this->object, $name);
                $this->assertFalse($this->result->hasChildren());

                $iterator = new RecursiveArrayIterator(self::$data);
                $this->object = new RecursiveIteratorIterator($iterator, RecursiveIteratorIterator::CHILD_FIRST);
                $this->result = new ArrayKeyFilterIterator($this->object, $name);
                $this->assertTrue($this->result->hasChildren());
                foreach ($this->result as $key => $val) {
                        $this->assertTrue($key == $name);
                        $this->assertTrue(isset($key));
                        $this->assertTrue(is_string($key));
                        printf("++ [name: %s] key: %s, val: %s\n", $name, $key, print_r($val, true));
                }
        }

}
