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

namespace UUP\Authentication {

        /**
         * Dummy class for unauthenticated sessions.
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

}

namespace UUP\Authentication\Stack {

        use UUP\Authentication,
            UUP\Authentication\Authenticator,
            UUP\Authentication\Exception;

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
         *              foreach($this->stack->authenticators as $key => $auth) {
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
         * @author Anders Lövgren (QNET/BMC CompDept)
         * @package UUP
         * @subpackage Authentication
         */
        class AuthenticatorStack extends AuthenticatorChain implements Authenticator
        {

                /**
                 * @var Authenticator Current active authenticator.
                 */
                private $authenticator;

                /**
                 * Constructor.
                 * @param AuthenticatorChain[] $chains Array of authenticator chains.
                 */
                public function __construct($chains = array())
                {
                        parent::__construct($chains);
                        $this->authenticator = new Authentication\NullAuthenticator();
                }

                /**
                 * Get current accepted authenticator.
                 * @return Authenticator
                 */
                public function getAuthenticator()
                {
                        return $this->authenticator;
                }

                /**
                 * Set the accepted authenticator that is going to be used for next call
                 * to login() or logout(). It can also be the authenticator already used 
                 * for an accepted login event.
                 * 
                 * @param Authenticator $authenticator The authenticator.
                 */
                public function setAuthenticator($authenticator)
                {
                        $this->authenticator = $authenticator;
                }

                /**
                 * Switch current active authenticator to the one associated with the given key.
                 * 
                 * This function is equivalent to:
                 * <code>
                 * $auth = $stack->authenticator($key);         // Find authenticator by key.
                 * $stack->setAuthenticator($auth->current());  // Set active authenticator.
                 * </code>
                 * 
                 * @param string $key The key for the authenticator.
                 */
                public function activate($key)
                {
                        $this->setAuthenticator($this->find($key)->current());
                }

                /**
                 * Get iterator for named chain.
                 * 
                 * Returns an iterator to all sub chains with a matching key. In
                 * most cases, all chains have a unique key so its safe to call
                 * $this->chains($key)->current().
                 * 
                 * @param string $key The chain key.
                 * @param bool $recursive In depth including sub chains.
                 * @return AuthenticatorChain|ChainFilterIterator
                 */
                public function chain($key, $recursive = true)
                {
                        if ($recursive) {
                                $search = new AuthenticatorSearch($this->chain);
                                return $search->chain($key);
                        } else {
                                $search = new AuthenticatorFilter($this->chain);
                                return $search->chain($key);
                        }
                }

                /**
                 * Get iterator for named authenticator.
                 * 
                 * Returns an iterator to all authenticators with a matching key. In
                 * most cases, all authenticators have a unique key so its safe to call
                 * $this->chains($key)->current().
                 * 
                 * @param string $key The chain key.
                 * @param bool $recursive In depth including sub chains.
                 * @return AuthenticatorBase|AuthenticatorFilterIterator
                 */
                public function authenticator($key, $recursive = true)
                {
                        if ($recursive) {
                                $search = new AuthenticatorSearch($this->chain);
                                return $search->authenticator($key);
                        } else {
                                $search = new AuthenticatorFilter($this->chain);
                                return $search->authenticator($key);
                        }
                }

                /**
                 * Get all authenticators in this stack.
                 * @return AuthenticatorFilterIterator
                 */
                private function authenticators()
                {
                        return (new AuthenticatorSearch($this->chain))->authenticators();
                }

                /**
                 * Check if any authenticator in the stack accepts the caller as a
                 * logged in user. Throws exception if user is not authenticated using
                 * a required authenticator.
                 * 
                 * @return bool
                 * @throws AuthenticatorRequiredException
                 */
                public function authenticated()
                {
                        if (!$this->authenticator->authenticated()) {
                                foreach ($this->authenticators() as $authenticator) {
                                        if ($authenticator->authenticated()) {
                                                if ($authenticator->control === Authenticator::sufficient) {
                                                        $this->authenticator = $authenticator;
                                                }
                                        } else {
                                                if ($authenticator->control === Authenticator::required) {
                                                        throw new AuthenticatorRequiredException($authenticator->authenticator);
                                                }
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

}
