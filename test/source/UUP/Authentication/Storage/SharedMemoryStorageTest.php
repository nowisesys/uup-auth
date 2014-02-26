<?php

namespace UUP\Authentication\Storage;

require_once 'StorageImplTest.php';

/**
 * Generated by PHPUnit_SkeletonGenerator 1.2.1 on 2014-02-26 at 16:44:44.
 */
class SharedMemoryStorageTest extends StorageImplTest
{

        /**
         * Sets up the fixture, for example, opens a network connection.
         * This method is called before a test is executed.
         */
        protected function setUp()
        {
                $this->object = new SharedMemoryStorage();
        }

        /**
         * Tears down the fixture, for example, closes a network connection.
         * This method is called after a test is executed.
         */
        protected function tearDown()
        {
                unset($this->object);
        }

}
