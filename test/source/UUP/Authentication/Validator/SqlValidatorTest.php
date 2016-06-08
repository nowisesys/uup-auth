<?php

namespace UUP\Authentication\Validator;

use PDO;
use UUP\Authentication\Validator\SqlValidator;
use UUP\Authentication\Validator\SqlValidatorHelper;

class SqlValidatorHelper extends SqlValidator
{

        const user = "admin";
        const pass = "admin";

        public function __construct()
        {
                parent::__construct(new PDO('sqlite::memory:', null, null, array(PDO::ERRMODE_EXCEPTION => true, PDO::ATTR_PERSISTENT => true)));

                $this->create();
                $this->add(self::user, self::pass);
        }

        private function create()
        {
                $sql = sprintf("CREATE TABLE %s(%s VARCHAR(10), %s VARCHAR(10))", parent::TABLE, parent::FUSER, parent::FPASS);
                $this->exec($sql);
        }

        public function add($user, $pass)
        {
                $sql = sprintf("INSERT INTO %s VALUES('%s', '%s')", parent::TABLE, $user, $pass);
                $this->exec($sql);
        }

}

/**
 * Generated by PHPUnit_SkeletonGenerator 1.2.1 on 2014-02-27 at 13:26:50.
 */
class SqlValidatorTest extends \PHPUnit_Framework_TestCase
{

        /**
         * @var SqlValidatorHelper
         */
        protected $object;

        /**
         * Sets up the fixture, for example, opens a network connection.
         * This method is called before a test is executed.
         */
        protected function setUp()
        {
                $this->object = new SqlValidatorHelper();
        }

        /**
         * Tears down the fixture, for example, closes a network connection.
         * This method is called after a test is executed.
         */
        protected function tearDown()
        {
                
        }

        /**
         * @covers UUP\Authentication\Validator\SqlValidator::authenticate
         */
        public function testAuthenticate()
        {
                $this->assertEquals($this->object->authenticate(), false);
                $this->object->setCredentials("", "");
                $this->assertEquals($this->object->authenticate(), false);

                $this->object->setCredentials("adam", "bertil");
                $this->assertEquals($this->object->authenticate(), false);
                $this->object->add("adam", "bertil");
                $this->assertEquals($this->object->authenticate(), true);

                $this->object->setCredentials(SqlValidatorHelper::user, SqlValidatorHelper::pass);
                $this->assertEquals($this->object->authenticate(), true);
        }

}
