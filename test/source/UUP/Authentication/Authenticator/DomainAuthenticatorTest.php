<?php

namespace UUP\Authentication\Authenticator;

/**
 * Generated by PHPUnit_SkeletonGenerator on 2015-04-09 at 00:43:17.
 */
class DomainAuthenticatorTest extends \PHPUnit_Framework_TestCase
{

        /**
         * @var DomainAuthenticator
         */
        protected $object;

        /**
         * Sets up the fixture, for example, opens a network connection.
         * This method is called before a test is executed.
         */
        protected function setUp()
        {
                $this->object = new DomainAuthenticator();
                $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        }

        /**
         * Tears down the fixture, for example, closes a network connection.
         * This method is called after a test is executed.
         */
        protected function tearDown()
        {
                
        }

        /**
         * @covers UUP\Authentication\Authenticator\DomainAuthenticator::accepted
         */
        public function testAccepted()
        {
                $this->object->setHostname("|^.*\.example\.com$|");
                self::assertFalse($this->object->accepted());

                self::assertFalse($this->object->match("www.google.com"));
                self::assertTrue($this->object->match("www.example.com"));

                $this->object->setHostname("|^.*\.se$|");
                self::assertFalse($this->object->match("www.google.com"));
                self::assertTrue($this->object->match("www.google.se"));

                $this->object->setHostname("|^www[0-9]\.example\.com$|");
                self::assertFalse($this->object->match("www.example.com"));
                self::assertFalse($this->object->match("www10.example.com"));
                self::assertTrue($this->object->match("www0.example.com"));
                self::assertTrue($this->object->match("www9.example.com"));

                $this->object->setHostname("|^.*$|");
                self::assertTrue($this->object->match("www.google.com"));
                self::assertTrue($this->object->match("www.google.se"));
                self::assertTrue($this->object->match("localhost"));
        }

        /**
         * @covers UUP\Authentication\Authenticator\DomainAuthenticator::getSubject
         */
        public function testGetSubject()
        {
                self::assertNull($this->object->getSubject());
                $this->object->setHostname("|^.*\.example\.com$|");
                $this->object->match("www.example.se");
                self::assertNull($this->object->getSubject());
                $this->object->match("www.example.com");
                self::assertNotNull($this->object->getSubject());
                self::assertEquals($this->object->getSubject(), "www.example.com");
        }

}
