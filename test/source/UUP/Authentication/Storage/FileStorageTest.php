<?php

namespace UUP\Authentication\Storage;

/**
 * Generated by PHPUnit_SkeletonGenerator 1.2.1 on 2014-02-26 at 12:08:43.
 */
class FileStorageTest extends \PHPUnit_Framework_TestCase
{

        /**
         * @var FileStorage
         */
        protected $object;

        /**
         * Sets up the fixture, for example, opens a network connection.
         * This method is called before a test is executed.
         */
        protected function setUp()
        {
                $this->object = new FileStorage(tempnam(sys_get_temp_dir(), __CLASS__));
        }

        /**
         * Tears down the fixture, for example, closes a network connection.
         * This method is called after a test is executed.
         */
        protected function tearDown()
        {
                
        }

        /**
         * @covers UUP\Authentication\Storage\FileStorage::exist
         * @todo   Implement testExist().
         */
        public function testExist()
        {
                // Remove the following lines when you implement this test.
                $this->markTestIncomplete(
                    'This test has not been implemented yet.'
                );
        }

        /**
         * @covers UUP\Authentication\Storage\FileStorage::insert
         * @todo   Implement testInsert().
         */
        public function testInsert()
        {
                // Remove the following lines when you implement this test.
                $this->markTestIncomplete(
                    'This test has not been implemented yet.'
                );
        }

        /**
         * @covers UUP\Authentication\Storage\FileStorage::remove
         * @todo   Implement testRemove().
         */
        public function testRemove()
        {
                // Remove the following lines when you implement this test.
                $this->markTestIncomplete(
                    'This test has not been implemented yet.'
                );
        }

}
