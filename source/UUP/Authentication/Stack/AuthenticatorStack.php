<?php

/*
 * Copyright (C) 2014-2015 Anders Lövgren (QNET/BMC CompDept).
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

use UUP\Authentication\Authenticator\Authenticator;
use UUP\Authentication\Authenticator\NullAuthenticator;
use UUP\Authentication\Exception;
use UUP\Authentication\Library\Authenticator\AuthenticatorBase;
use UUP\Authentication\Restrictor\Restrictor;
use UUP\Authentication\Stack\Filter\AuthenticatorFilterIterator;
use UUP\Authentication\Stack\Filter\ChainFilterIterator;
use UUP\Authentication\Stack\Filter\VisibilityFilterIterator;

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
 *              if($this->stack->accepted()) {
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
 * if(!$stack->accepted()) {
 *      header("location: /logon");     // Redirect to logon page
 * }
 * </code>
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
 * @package UUP
 * @subpackage Authentication
 */
class AuthenticatorStack extends AuthenticatorChain implements Authenticator, Restrictor
{

        /**
         * @var Authenticator|Restrictor Current active authenticator.
         */
        private $_authenticator;

        /**
         * Constructor.
         * @param AuthenticatorChain[] $chains Array of authenticator chains.
         */
        public function __construct($chains = array())
        {
                parent::__construct($chains);
                $this->_authenticator = new NullAuthenticator();
        }

        /**
         * Get current accepted authenticator.
         * @return Authenticator
         */
        public function getAuthenticator()
        {
                return $this->_authenticator;
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
                $this->_authenticator = $authenticator;
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
                $this->setAuthenticator($this->authenticator($key)->current());
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
                        $search = new AuthenticatorSearch($this->_chain);
                        return $search->chain($key);
                } else {
                        $search = new AuthenticatorFilter($this->_chain);
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
                        $search = new AuthenticatorSearch($this->_chain);
                        return $search->authenticator($key);
                } else {
                        $search = new AuthenticatorFilter($this->_chain);
                        return $search->authenticator($key);
                }
        }

        /**
         * Get all authenticators in this stack.
         * @param bool $visible Only include authenticators with the visibility property equals to true.
         * @return AuthenticatorBase[]|AuthenticatorFilterIterator
         */
        public function authenticators($visible = false)
        {
                if ($visible) {
                        return new VisibilityFilterIterator((new AuthenticatorSearch($this->_chain))->authenticators());
                } else {
                        return (new AuthenticatorSearch($this->_chain))->authenticators();
                }
        }

        /**
         * Check if any authenticator in the stack accepts the caller as a
         * logged in user. Throws exception if user is not authenticated using
         * a required authenticator.
         * 
         * @return bool
         * @throws AuthenticatorRequiredException
         */
        public function accepted()
        {
                if (!$this->_authenticator->accepted()) {
                        foreach ($this->authenticators() as $authenticator) {
                                if ($authenticator->control === Authenticator::REQUIRED) {
                                        if (!$authenticator->accepted()) {
                                                throw new AuthenticatorRequiredException($authenticator->authenticator);
                                        }
                                }
                        }
                        foreach ($this->authenticators() as $authenticator) {
                                if ($authenticator->control === Authenticator::SUFFICIENT &&
                                    $authenticator->accepted()) {
                                        $this->_authenticator = $authenticator;
                                        break;
                                }
                        }
                }
                return $this->_authenticator->accepted();
        }

        /**
         * Get username from current accepted authenticator.
         * @return string 
         */
        public function getSubject()
        {
                return $this->_authenticator->getSubject();
        }

        /**
         * Login using currently selected authenticator.
         * @throws Exception
         */
        public function login()
        {
                $this->_authenticator->login();
        }

        /**
         * Logout using currently selected authenticator.
         */
        public function logout()
        {
                if ($this->accepted()) {
                        $this->_authenticator->logout();
                }
        }

}
