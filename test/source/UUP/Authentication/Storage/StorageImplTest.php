<?php

namespace UUP\Authentication\Storage;

/**
 * Runs unit test using object implementing the Storage interface.
 *
 * @author Anders Lövgren (Computing Department at BMC, Uppsala University)
 */
class StorageImplTest extends \PHPUnit_Framework_TestCase
{

        /**
         * @var Storage 
         */
        protected $object;

        /**
         * @covers UUP\Authentication\Storage\FileStorage::exist
         */
        public function testExist()
        {
                $user = "olle";
                $this->assertEquals($this->object->exist($user), false);
                $this->object->insert($user);
                $this->assertEquals($this->object->exist($user), true);
                $user = "adam";
                $this->assertEquals($this->object->exist($user), false);
        }

        /**
         * @covers UUP\Authentication\Storage\FileStorage::insert
         */
        public function testInsert()
        {
                $this->testExist();
        }

        /**
         * @covers UUP\Authentication\Storage\FileStorage::remove
         */
        public function testRemove()
        {
                $user = "olle";
                $this->object->insert($user);
                $this->assertEquals($this->object->exist($user), true);
                $this->object->remove($user);
                $this->assertEquals($this->object->exist($user), false);
        }
        
}
