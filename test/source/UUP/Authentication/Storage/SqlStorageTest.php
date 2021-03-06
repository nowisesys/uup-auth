<?php

namespace UUP\Authentication\Storage;

use PDO;
use UUP\Authentication\Storage\SqlStorage;
use UUP\Authentication\Storage\StorageImplBase;

require_once 'StorageImplBase.php';

/**
 * Generated by PHPUnit_SkeletonGenerator 1.2.1 on 2014-02-26 at 16:52:59.
 */
class SqlStorageTest extends StorageImplBase
{

        private $pdo;

        public function __construct()
        {
                $this->pdo = new PDO('sqlite::memory:', null, null);
                $this->sql = sprintf("CREATE TABLE %s(%s varchar(10))", SqlStorage::TABLE, SqlStorage::FUSER);
                $this->pdo->exec($this->sql);
        }

        /**
         * Sets up the fixture, for example, opens a network connection.
         * This method is called before a test is executed.
         */
        protected function setUp()
        {
                $this->object = new SqlStorage($this->pdo);
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
