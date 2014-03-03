<?php

/*
 * Copyright (C) 2014 Anders Lövgren (QNET/BMC CompDept).
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

namespace UUP\Authentication\Stack;

use UUP\Authentication\Authenticator;
use UUP\Authentication\Exception;

/**
 * Plugin class for unauthenticated session.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class NullAuthenticator implements Authenticator
{

        public function authenticated()
        {
                return false;
        }

        public function getUser()
        {
                return "";
        }

        public function login()
        {
                // ignore
        }

        public function logout()
        {
                // ignore
        }

}

/**
 * The stack of authenticator objects. 
 * 
 * This class can be used to support multiple authentication methods in a uniform 
 * way. This example should describle the basic usage of this class:
 * <code>
 * // 
 * // logon.php handles /{login|logoff}/{method=key}
 * // 
 * 
 * $stack->add("cas", $authcas, "CAS Server");
 * $stack->add("msad", $authad, "Microsoft Active Directory");
 * 
 * class LogonController
 * {
 *      // ...
 * 
 *      public function logoff()
 *      {
 *              if($this->stack->authenticated()) {
 *                      $this->stack->logoff();       // Using current selected authenticator.
 *              }
 *      }
 * 
 *      public function login($method)
 *      {
 *              if(isset($method)) {
 *                      $this->stack->activate($method);
 *                      $this->stack->login();
 *              } else {
 *                      $view = new LogonView($this->stack);
 *                      $view->render();
 *              }
 *      }
 * }
 * 
 * class LogonView extends BasicView
 * {
 *      // ...
 * 
 *      public function render() 
 *      {
 *              printf("<h1>Select login method</h1>\n");
 *              printf("<ul>\n");
 *              foreach($stack->authenticators as $key => $auth) {
 *                      printf("<li><a href=\"?login=1&method=%s\" title=\"%s\">%s</a>\n", 
 *                              $key, $auth->description, $auth->name);
 *              }
 *              printf("</ul>\n");
 *      }
 * }
 * 
 * // 
 * // Login required on some other page:
 * // 
 * 
 * if(!$stack->authenticated()) {
 *      header("location: /logon");     // Redirect to logon page
 * }
 * </code>
 * 
 * @property-read AuthenticatorDecorator[] $authenticators Associative array of all authenticators.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class AuthenticatorStack implements Authenticator
{

        /**
         * @var AuthenticatorDecorator[] Associative array of all authenticators. 
         */
        private $authenticators;
        /**
         * @var AuthenticatorDecorator Current accepted authenticator.
         */
        private $authenticator;

        /**
         * Constructor.
         * @param AuthenticatorDecorator[] $authenticators
         */
        public function __construct($authenticators = array())
        {
                $this->authenticators = $authenticators;
                $this->authenticator = new NullAuthenticator();
        }

        public function __get($name)
        {
                if ($name == 'authenticators') {
                        return $this->authenticators;
                }
        }

        /**
         * Adds an authenticator to the authenticator stack.
         * @param string $key The key for this authenticator.
         * @param Authenticator $auth The autenticator object.
         * @param string $name Short name for wrapped authenticator.
         * @param string $desc Longer descriptive text for wrapped authenticator.
         * @return AuthenticatorDecorator
         */
        public function add($key, $auth, $name = "", $desc = "")
        {
                $this->authenticators[$key] = new AuthenticatorDecorator($auth, $name, $desc);
                return $this->authenticators[$key];
        }

        /**
         * Get current accepted authenticator.
         * @return AuthenticatorDecorator
         */
        public function current()
        {
                return $this->authenticator;
        }

        /**
         * Switch current active authenticator to the one associated with the given key.
         * @param string $key The key for the authenticator.
         */
        public function activate($key)
        {
                $this->set($this->get($key));
        }

        /**
         * Get authenticator associated with given key.
         * @param string $key The key for the authenticator.
         * @return AuthenticatorDecorator
         */
        public function get($key)
        {
                return $this->authenticators[$key];
        }

        /**
         * Set the accepted authenticator that is going to be used for next call
         * to login() or logout(). It can also be the authenticator already used 
         * for an accepted login event.
         * 
         * @param AuthenticatorDecorator $auth The authenticator.
         */
        public function set($auth)
        {
                $this->authenticator = $auth;
        }

        /**
         * Check if any authenticator in the stack accepts the caller as 
         * a logged in user. 
         * @return bool
         */
        public function authenticated()
        {
                if (!$this->authenticator->authenticated()) {
                        foreach ($this->authenticators as $authenticator) {
                                if ($authenticator->authenticated()) {
                                        $this->authenticator = $authenticator;
                                }
                        }
                }
                return $this->authenticator->authenticated();
        }

        /**
         * Get username from current accepted authenticator.
         * @return string 
         */
        public function getUser()
        {
                return $this->authenticator->getUser();
        }

        /**
         * Login using currently selected authenticator.
         * @throws Exception
         */
        public function login()
        {
                $this->authenticator->login();
        }

        /**
         * Logout using currently selected authenticator.
         */
        public function logout()
        {
                $this->authenticator->logout();
        }

}
