<?php

namespace UUP\Authentication\Library\Authenticator;

use UUP\Authentication\Authenticator\Authenticator;
use UUP\Authentication\Library\Authenticator\AuthenticatorBase;
use UUP\Authentication\Library\Authenticator\DummyAuthenticator;
use UUP\Authentication\Restrictor\Restrictor;

class DummyAuthenticator extends AuthenticatorBase implements Authenticator, Restrictor
{

        public function accepted()
        {
                
        }

        public function getSubject()
        {
                
        }

        public function login()
        {
                
        }

        public function logout()
        {
                
        }

}

/**
 * Generated by PHPUnit_SkeletonGenerator 1.2.1 on 2014-03-10 at 01:26:44.
 */
class AuthenticatorBaseTest extends \PHPUnit_Framework_TestCase
{

        /**
         * @var Authenticator
         */
        protected $object;

        /**
         * Sets up the fixture, for example, opens a network connection.
         * This method is called before a test is executed.
         */
        protected function setUp()
        {
                $this->object = new DummyAuthenticator();
        }

        /**
         * Tears down the fixture, for example, closes a network connection.
         * This method is called after a test is executed.
         */
        protected function tearDown()
        {
                
        }

        public function testBuild()
        {
                $name = 'Name1';
                $description = 'Some description';
                $visible = true;
                $control = Authenticator::required;

                $this->object = (new DummyAuthenticator())
                    ->name($name)
                    ->description($description)
                    ->visible($visible)
                    ->control($control);
                $this->assertEquals($this->object->name, $name);
                $this->assertEquals($this->object->description, $description);
                $this->assertEquals($this->object->visible, $visible);
                $this->assertEquals($this->object->control, $control);
        }

        /**
         * @covers UUP\Authentication\Library\Authenticator\AuthenticatorBase::__get
         */
        public function test__get()
        {
                $name = 'Name1';
                $description = 'Some description';
                $visible = true;
                $control = Authenticator::required;

                $this->object->name($name);
                $this->object->description($description);
                $this->object->visible($visible);
                $this->object->control($control);

                $this->assertTrue($this->object->name == $name);
                $this->assertTrue($this->object->description == $description);
                $this->assertTrue($this->object->visible == $visible);
                $this->assertTrue($this->object->control == $control);
        }

        /**
         * @covers UUP\Authentication\Library\Authenticator\AuthenticatorBase::control
         */
        public function testControl()
        {
                $value = Authenticator::required;
                $this->object->control($value);
                $this->assertTrue($this->object->control == $value);
                $this->assertTrue(is_int($this->object->control));

                $value = Authenticator::sufficient;
                $this->object->control($value);
                $this->assertTrue($this->object->control == $value);
                $this->assertTrue(is_int($this->object->control));

                $value = null;
                $this->object->control($value);
                $this->assertTrue($this->object->control == 0);
                $this->assertTrue(is_int($this->object->control));
        }

        /**
         * @covers UUP\Authentication\Library\Authenticator\AuthenticatorBase::name
         */
        public function testName()
        {
                $value = 'Name1';
                $this->object->name($value);
                $this->assertTrue($this->object->name == $value);
                $this->assertTrue(is_string($this->object->name));

                $value = '';
                $this->object->name($value);
                $this->assertTrue($this->object->name == $value);
                $this->assertTrue(is_string($this->object->name));

                $value = null;
                $this->object->name($value);
                $this->assertTrue($this->object->name == '');
                $this->assertTrue(is_string($this->object->name));
        }

        /**
         * @covers UUP\Authentication\Library\Authenticator\AuthenticatorBase::description
         */
        public function testDescription()
        {
                $value = 'Some text';
                $this->object->description($value);
                $this->assertTrue($this->object->description == $value);
                $this->assertTrue(is_string($this->object->description));

                $value = "";
                $this->object->description($value);
                $this->assertTrue(is_string($this->object->description));
                $this->assertTrue($this->object->description == $value);

                $value = null;
                $this->object->description($value);
                $this->assertTrue(is_string($this->object->description));
                $this->assertTrue($this->object->description == "");
        }

        /**
         * @covers UUP\Authentication\Library\Authenticator\AuthenticatorBase::visible
         */
        public function testVisible()
        {
                $value = true;
                $this->object->visible($value);
                $this->assertTrue($this->object->visible);
                $this->assertTrue($this->object->visible == $value);
                $this->assertTrue(is_bool($this->object->visible));

                $value = false;
                $this->object->visible($value);
                $this->assertFalse($this->object->visible);
                $this->assertTrue($this->object->visible == $value);
                $this->assertTrue(is_bool($this->object->visible));

                $value = null;
                $this->object->visible($value);
                $this->assertFalse($this->object->visible);
                $this->assertTrue($this->object->visible == false);
                $this->assertTrue(is_bool($this->object->visible));
        }

        /**
         * @covers UUP\Authentication\Library\Authenticator\AuthenticatorBase::sufficient
         */
        public function testSufficient()
        {
                $value = Authenticator::sufficient;
                $this->object->control($value);
                $this->assertTrue($this->object->sufficient());

                $value = Authenticator::required;
                $this->object->control($value);
                $this->assertFalse($this->object->sufficient());
        }

        /**
         * @covers UUP\Authentication\Library\Authenticator\AuthenticatorBase::required
         */
        public function testRequired()
        {
                $value = Authenticator::required;
                $this->object->control($value);
                $this->assertTrue($this->object->required());

                $value = Authenticator::sufficient;
                $this->object->control($value);
                $this->assertFalse($this->object->required());
        }

}
