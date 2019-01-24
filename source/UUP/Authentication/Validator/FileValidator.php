<?php

/*
 * Copyright (C) 2017 Anders Lövgren (Nowise Systems).
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

namespace UUP\Authentication\Validator;

use UUP\Authentication\Exception;

/**
 * Decode newline/tab-separated data.
 * 
 * @param string $data The input data.
 * @return array
 */
function tab_decode($data)
{
        $lines = explode("\n", $data);

        foreach ($lines as $index => $line) {
                $lines[$index] = explode("\t", $line);
        }

        return $lines;
}

/**
 * Abstract base class for backends.
 */
abstract class FileValidatorBackend
{

        /**
         * The user/pass column map.
         * @var array
         */
        private $_colmap;

        /**
         * Constructor.
         * @param array $colmap The user/pass column map.
         */
        public function __construct($colmap)
        {
                $this->_colmap = $colmap;
        }

        /**
         * Check if user/pass exist in data.
         * 
         * @param array $data The input data.
         * @param string $user The username.
         * @param string $pass The password.
         * @return boolean
         */
        protected function exists($data, $user, $pass)
        {
                $colmap = $this->_colmap;

                foreach ($data as $key => $arr) {
                        // 
                        // Reset colmap if data is user => pass entries.
                        // 
                        if (is_string($arr)) {
                                $colmap = array('user' => false, 'pass' => false);
                        }
                        
                        // 
                        // Check username:
                        // 
                        if ($colmap['user']) {
                                if ($arr[$colmap['user']] != $user) {
                                        continue;
                                }
                        } elseif (is_array($arr)) {
                                if (!in_array($user, $arr))
                                        continue;
                        } else {
                                if ($user != $key) {
                                        continue;
                                }
                        }

                        // 
                        // Check password:
                        // 
                        if ($colmap['pass']) {
                                if ($arr[$colmap['pass']] != $pass) {
                                        continue;
                                }
                        } elseif (is_array($arr)) {
                                if (!in_array($pass, $arr))
                                        continue;
                        } else {
                                if ($pass != $arr) {
                                        continue;
                                }
                        }

                        // 
                        // Username and password found:
                        // 
                        return true;
                }

                // 
                // Not found in data:
                // 
                return false;
        }

        /**
         * Validate credentials against file.
         * 
         * @param string $file The input file.
         * @param string $user The username.
         * @param string $pass The password.
         * @return boolean
         */
        abstract function validate($file, $user, $pass);
}

/**
 * Validate against PHP serialized data.
 */
class FileValidatorSerialized extends FileValidatorBackend
{

        public function validate($file, $user, $pass)
        {
                if (!($data = unserialize(file_get_contents($file)))) {
                        return false;
                } else {
                        return parent::exists($data, $user, $pass);
                }
        }

}

/**
 * Validate against JSON data.
 */
class FileValidatorJson extends FileValidatorBackend
{

        public function validate($file, $user, $pass)
        {
                if (!($data = json_decode(file_get_contents($file), true))) {
                        return false;
                } else {
                        return parent::exists($data, $user, $pass);
                }
        }

}

/**
 * Validate against tab-separated data.
 */
class FileValidatorTab extends FileValidatorBackend
{

        public function validate($file, $user, $pass)
        {
                if (!($data = tab_decode(file_get_contents($file)))) {
                        return false;
                } else {
                        return parent::exists($data, $user, $pass);
                }
        }

}

/**
 * Validate user againt "plain text" file.
 * 
 * The input data should have user name as keys and password as value (for PHP serialized 
 * and JSON encoded format). For tab-separated, then first column is username and the second 
 * column contains password.
 * 
 * The prefered format is PHP serialized and is also the default format. No exception is throwed
 * if unserialize fails because input data might be a empty file.
 * 
 * <code>
 * // 
 * // Username is in second column and password in third:
 * // 
 * $columnmap = array('user' => 1, 'pass' => 2);
 * 
 * // 
 * // Validate user credentials:
 * // 
 * $validator = new FileValidator('file.tab', FileValidator::TAB);
 * $validator->setCredentials($user, $pass);
 * 
 * if ($validator->authenticate()) {
 *      // Successful validated credentials
 * }
 * </code>
 * 
 * The column map can reference user/pass columns with numeric index or keys:
 * <code>
 * $columnmap = array('user' => 0, 'pass' => 1);        // Default
 * $columnmap = array('user' => 1, 'pass' => 0);        // Swapped order
 * $columnmap = array('user' => 2, 'pass' => 3);        // Offset
 * $columnmap = array('user' => 'u', 'pass' => 'p');    // Using key names (not for tab-separated)
 * </code>
 * 
 * If column map has false as user/pass columns, the user/pass is matched on any column in
 * input data. This is not recommended.
 * 
 * @property-write string $file The file path.
 * @property-write int $format The file format.
 * @property-write array $colmap The user/pass to array index map.
 * 
 * @author Anders Lövgren (Nowise Systems/Uppsala University)
 * @package UUP
 * @subpackage Authentication
 */
class FileValidator extends CredentialValidator
{

        /**
         * PHP serialized data.
         */
        const FORMAT_PHP = 1;
        /**
         * JSON encoded data.
         */
        const FORMAT_JSON = 2;
        /**
         * Tab separated data.
         */
        const FORMAT_TAB = 3;

        /**
         * The file path.
         * @var string 
         */
        private $_file;
        /**
         * The file format.
         * @var int 
         */
        private $_format;
        /**
         * The user/pass to array index map.
         * @var array 
         */
        private $_colmap = array('user' => 0, 'pass' => 1);

        /**
         * Constructor.
         * 
         * @param string $file The file path.
         * @param int $format The file format.
         */
        public function __construct($file = 'user.dat', $format = self::FORMAT_PHP)
        {
                $this->_file = $file;
                $this->_format = $format;
        }

        public function __set($name, $value)
        {
                switch ($name) {
                        case 'file':
                                $this->_file = (string) $value;
                                break;
                        case 'format':
                                $this->_format = (int) $value;
                                break;
                        case 'colmap':
                                $this->_colmap = (array) $value;
                                break;
                }
        }

        /**
         * Destructor.
         */
        public function __destruct()
        {
                parent::__destruct();
                $this->_file = null;
        }

        /**
         * Authenticate using currently set credentials. Returns true if authentication succeed.
         * @return bool 
         * @throws Exception
         */
        public function authenticate()
        {
                if (!isset($this->_user) || strlen($this->_user) == 0) {
                        return false;
                }
                if (!file_exists($this->_file)) {
                        throw new Exception(sprintf("The input file %s don't exist in file validator.", $this->_file));
                }
                if (!is_readable($this->_file)) {
                        throw new Exception(sprintf("The input file %s is not readable in file validator.", $this->_file));
                }

                switch ($this->_format) {
                        case self::FORMAT_PHP:
                                $validator = new FileValidatorSerialized($this->_colmap);
                                break;
                        case self::FORMAT_JSON:
                                $validator = new FileValidatorJson($this->_colmap);
                                break;
                        case self::FORMAT_TAB:
                                $validator = new FileValidatorTab($this->_colmap);
                                break;
                }

                if ($validator->validate($this->_file, $this->_user, $this->_pass)) {
                        $validator = null;
                        return true;
                } else {
                        $validator = null;
                        return false;
                }
        }

}
