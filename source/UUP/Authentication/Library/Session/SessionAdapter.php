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
 * The interface for extern session handler.
 * 
 * @author Anders Lövgren (QNET)
 * @package UUP
 * @subpackage Authentication
 */
interface SessionAdapter
{

        /**
         * Session is active.
         */
        const ACTIVE = PHP_SESSION_ACTIVE;
        /**
         * Session handling is disabled.
         */
        const DISABLED = PHP_SESSION_DISABLED;
        /**
         * Session is not started.
         */
        const MISSING = PHP_SESSION_NONE;

        /**
         * Get session status.
         * @return int The session status.
         */
        function status();

        /**
         * Write session data.
         * 
         * If close is true, then the session is closed on finish.
         * @param bool $close Close session on return.
         */
        function write($close = true);

        /**
         * Start session.
         * 
         * @param array $options The session options.
         * @return bool
         */
        function start($options = []);

        /**
         * Session is started.
         * @return bool 
         */
        function started();

        /**
         * Regenerate session ID.
         * @return int
         */
        function regenerate($delete = false);
}
