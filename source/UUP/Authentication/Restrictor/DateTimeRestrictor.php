<?php

/*
 * Copyright (C) 2014-2016 Anders Lövgren (QNET/BMC CompDept).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace UUP\Authentication\Restrictor;

use UUP\Authentication\Authenticator\Authenticator;
use UUP\Authentication\Library\Authenticator\AuthenticatorBase;
use UUP\Authentication\Restrictor\Restrictor;

/**
 * DateTime restrictor.
 * 
 * This class is intended to be used for access restriction based on start and
 * end time. It could be used as a required authenticator in an authenticator
 * stack for denying access outside of a daily period or a time interval.
 * 
 * Example for restriction to a daily recurring interval when access is allowed:
 * <code>
 * class AccessRestrictor extends DateTimeRestrictor
 * {
 * 
 *      public function authenticate()
 *      {
 *              if(!parent::authenticate()) {
 *                      die(sprintf("Service only available between %s and %s", 
 *                                   self::format($this->stime),
 *                                   self::format($this->etime)));
 *              }
 *      }
 * 
 *      private static function format($stamp)
 *      {
 *              return strftime("%x %X", $stamp);
 *      }
 * }
 * 
 * $stime = mktime(8, 30, 0);   // start time
 * $etime = mktime(16, 0, 0);   // end time
 * 
 * $restrictor = new AccessRestrictor($stime, $etime);
 * $restrictor->authenticate();      // kill script outside of access time period.
 * </code>
 * 
 * @property-read int $start The start time (UNIX timestamp).
 * @property-read int $end The end time (UNIX timestamp).
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class DateTimeRestrictor extends AuthenticatorBase implements Restrictor
{

        /**
         * @var int 
         */
        protected $_stime;
        /**
         * @var int 
         */
        protected $_etime;

        /**
         * Constructor.
         * @param int $stime The start time (UNIX timestamp).
         * @param int $etime The end time (UNIX timestamp).
         */
        public function __construct($stime, $etime)
        {
                parent::__construct();
                
                $this->_stime = $stime;
                $this->_etime = $etime;
                
                $this->visible(false);
                $this->control(Authenticator::REQUIRED);
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                parent::__destruct();
                
                $this->_stime = null;
                $this->_etime = null;
        }
        
        public function __get($name)
        {
                switch ($name) {
                        case 'start':
                                return $this->_stime;
                        case 'end':
                                return $this->_etime;
                        default :
                                return parent::__get($name);
                }
        }

        /**
         * Check if datetime is accepted.
         * @return boolean
         */
        public function accepted()
        {
                return ($this->_stime <= time()) && (time() <= $this->_etime);
        }

        /**
         * Get accepted datetime.
         * @return string
         */
        public function getSubject()
        {
                return strftime("%x %X", time());
        }

}
