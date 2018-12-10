<?php

/*
 * Copyright (C) 2014-2017 Anders Lövgren (Nowise Systems/Uppsala University).
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

namespace UUP\Authentication\Authenticator;

use UUP\Authentication\Storage\SessionStorage;
use UUP\Authentication\Validator\Validator;

/**
 * HTML form authenticator.
 * 
 * This class authenticates a user based on request parameters. The request 
 * parameters can i.e. be obtained from a submitted form. Notice that this 
 * class is kind of generic, it could also be used to provide authentication
 * for simple GET requests.
 * 
 * This class is suitable for a simple web application using PHP sessions to
 * identify users and using a form based logon. The only requirement in that 
 * case is to supply an user validator (could be LDAP or SQL).
 * 
 * These are the default options unless overridden by the options argument
 * for the constructor:
 * 
 * <code>
 * $options = array(
 *      'login'  => '/login',   // Login form URL.
 *      'name'   => 'auth',     // The form name.
 *      'user'   => 'user',     // Request parameter containing the username.
 *      'pass'   => 'pass'      // Request parameter containing the password.
 * );
 * </code>
 * 
 * Lets say that /login/ldap is an URL for obtaining the credentials for 
 * authentication against an LDAP server. Then this class can be used like
 * this:
 * <code>
 * $auth = new FormAuthenticator(
 *      new LdapBindValidator('ldaps://ldap.example.com'),
 *      array('login' => '/login/ldap', 'name' => 'authldap')
 * );
 * </code>
 * 
 * In contrast to the other authenticators the form authenticator don't have 
 * constant access to the username. Its only present when supplied as a POST
 * or GET request parameter, typical when called as part of a REST request or
 * in response to a form submit.
 * 
 * To overcome this limitation, the FormAuthenticator uses a SessionStorage 
 * object to persist the authenticated username between requests. The session
 * storage can be overridden by passing a third argument to the constructor.
 * 
 * @property-read string $name Unique form name, i.e. from hidden field or submit button.
 * @property-read string $user The username request parameter name.
 * @property-read string $pass The password request parameter name.
 * 
 * @author Anders Lövgren (Nowise Systems/Uppsala University)
 * @package UUP
 * @subpackage Authentication
 */
class FormAuthenticator extends RequestAuthenticator
{

        /**
         * The session storage.
         * @var SessionStorage 
         */
        private $_session;

        /**
         * Constructor.
         * 
         * @param Validator $validator The validator callback object.
         * @param array $options Options for request parameters.
         * @param SessionStorage $session The session storage.
         */
        public function __construct($validator, $options = array(), $session = null)
        {
                parent::__construct($validator, $options);

                if (isset($session)) {
                        $this->_session = $session;
                } else {
                        $this->_session = new SessionStorage($this->_options['name'], false);
                }
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                parent::__destruct();
                $this->_session = null;
        }

        /**
         * Check if session storage has user.
         * @return boolean
         */
        public function accepted()
        {
                $sess = $this->_session;
                $data = $sess->read();

                if ($sess->exist($data->user)) {
                        return true;
                }
                if (parent::accepted()) {
                        $sess->insert(parent::getSubject());
                        return true;
                }

                return false;
        }

        /**
         * Get user from session storage.
         * @return string
         */
        public function getSubject()
        {
                $sess = $this->_session;
                $data = $sess->read();

                if (($data->user != null)) {
                        return $data->user;
                } else {
                        return parent::getSubject();
                }
        }

        /**
         * Logout and remove user from session storage.
         */
        public function logout()
        {
                $sess = $this->_session;
                $data = $sess->read();

                $sess->remove($data->user);
                parent::logout();
        }

}
