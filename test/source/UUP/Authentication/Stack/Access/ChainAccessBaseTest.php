<?php

namespace UUP\Authentication\Stack\Access;

use UUP\Authentication\Stack\AuthenticatorChain;

require_once __DIR__ . '/ChainAccessObject.php';

/**
 * Chain accessor implementation.
 */
class ChainAccessBaseImpl extends ChainAccessBase
{

        public $object;

        public function __construct()
        {
                $this->object = new ChainAccessObject();
                parent::__construct(
                    new AuthenticatorChain(array('obj1' => $this->object))
                );
        }

        public function exist($name)
        {
                return parent::exist($name);
        }

        public function get($name)
        {
                return parent::get($name);
        }

        public function set($name, $value)
        {
                parent::set($name, $value);
        }

        public function remove($name)
        {
                parent::remove($name);
        }

}

/**
 * Generated by PHPUnit_SkeletonGenerator 1.2.1 on 2014-03-12 at 18:35:49.
 */
class ChainAccessBaseTest extends \PHPUnit_Framework_TestCase
{

        /**
         * @var ChainAccessBaseImpl
         */
        protected $chain;

        /**
         * Sets up the fixture, for example, opens a network connection.
         * This method is called before a test is executed.
         */
        protected function setUp()
        {
                $this->chain = new ChainAccessBaseImpl();
        }

        /**
         * Tears down the fixture, for example, closes a network connection.
         * This method is called after a test is executed.
         */
        protected function tearDown()
        {
                
        }

        /**
         * @covers UUP\Authentication\Stack\Access\ChainAccessBase::exist
         */
        public function testExist()
        {
                $this->assertTrue($this->chain->exist('obj1'));
        }

        /**
         * @covers UUP\Authentication\Stack\Access\ChainAccessBase::get
         */
        public function testGet()
        {
                $obj1 = $this->chain->get('obj1');
                $this->assertNotNull($obj1);
                $this->assertTrue($obj1 instanceof ChainAccessObject);
                $this->assertTrue($obj1 === $this->chain->object);
        }

        /**
         * @covers UUP\Authentication\Stack\Access\ChainAccessBase::set
         */
        public function testSet()
        {
                $obj2 = new ChainAccessObject();
                $this->chain->set('obj2', $obj2);

                $obj1 = $this->chain->get('obj1');
                $objc = $this->chain->get('obj2');

                $this->assertNotNull($objc);
                $this->assertTrue($objc instanceof ChainAccessObject);
                $this->assertTrue($objc === $obj2);
                $this->assertTrue($objc !== $obj1);
                $this->assertTrue($objc !== $this->chain->object);
        }

        /**
         * @covers UUP\Authentication\Stack\Access\ChainAccessBase::remove
         */
        public function testRemove()
        {
                // 
                // Notice: A new empty authenticator chain is created when calling 
                // get on non-existing object in chain.
                // 
                $this->chain->remove('obj1');
                $obj1 = $this->chain->get('obj1');
                $this->assertTrue($obj1 instanceof AuthenticatorChain);
        }

}