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
 *                                   $this->_sdate, 
 *                                   $this->_edate
 *                      ));
 *              }
 *      }
 * }
 * 
 * $restrictor = new AccessRestrictor('08:30', '16:45');
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
         * Format string for datetime.
         */
        const DATETIME_FORMAT = '%x %X';

        /**
         * The start time (UNIX timestamp).
         * @var int 
         */
        protected $_stime;
        /**
         * The end time (UNIX timestamp).
         * @var int 
         */
        protected $_etime;
        /**
         * The start time (as datetime string).
         * @var string
         */
        protected $_sdate;
        /**
         * The end time (as datetime string).
         * @var string
         */
        protected $_edate;

        /**
         * Constructor.
         * @param int $stime The start time (UNIX timestamp).
         * @param int $etime The end time (UNIX timestamp).
         */
        public function __construct($stime, $etime, $format = null)
        {
                parent::__construct();

                if (is_string($stime)) {
                        $stime = strtotime($stime);
                }
                if (is_string($etime)) {
                        $etime = strtotime($etime);
                }
                if (!isset($format)) {
                        $format = self::DATETIME_FORMAT;
                }

                $this->_stime = $stime;
                $this->_etime = $etime;

                $this->_sdate = strftime($format, $stime);
                $this->_edate = strftime($format, $etime);

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

                $this->_sdate = null;
                $this->_edate = null;
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

        public function __toString()
        {
                return sprintf("%s - %s", $this->_sdate, $this->_edate);
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
