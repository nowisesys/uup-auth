<?php

/*
 * Copyright (C) 2018 Anders Lövgren (QNET).
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

namespace UUP\Authentication\Library\Session;

/**
 * The native session handler.
 *
 * @author Anders Lövgren (QNET)
 * @package UUP
 * @subpackage Authentication
 */
class SessionNative implements SessionAdapter
{

        /**
         * Regenerate session ID.
         * @return int
         */
        public function regenerate($delete = false)
        {
                return session_regenerate_id($delete);
        }

        /**
         * Start session.
         * 
         * @param array $options The session options.
         * @return bool
         */
        public function start($options = [])
        {
                return session_start($options);
        }

        /**
         * Session is started.
         * @return bool 
         */
        public function started()
        {
                return session_status() == self::ACTIVE;
        }

        /**
         * Get session status.
         * @return int The session status.
         */
        public function status()
        {
                return session_status();
        }

        /**
         * Write session data.
         * 
         * If close is true, then the session is closed on finish.
         * @param bool $close Close session on return.
         */
        public function write($close = true)
        {
                if ($close) {
                        session_write_close();
                }
        }

}
