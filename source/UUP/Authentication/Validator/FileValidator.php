<?php

/*
 * Copyright (C) 2017 Anders Lövgren (QNET).
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
 * Interface for file validator backends.
 */
interface FileValidatorBackend
{

        /**
         * Validate user/pass against file.
         * 
         * @param string $file The file path.
         * @param string $user The username.
         * @param string $pass The password.
         * @return bool 
         */
        function validate($file, $user, $pass);
}

/**
 * Validate against PHP serialized data.
 */
class FileValidatorSerialized implements FileValidatorBackend
{

        public function validate($file, $user, $pass)
        {
                if (!($data = unserialize(file_get_contents($file)))) {
                        return false;
                }

                if (!array_key_exists($user, $data)) {
                        return false;
                }
                if (!($data[$user] == $pass)) {
                        return false;
                }

                return true;
        }

}

/**
 * Validate against JSON data.
 */
class FileValidatorJson implements FileValidatorBackend
{

        public function validate($file, $user, $pass)
        {
                if (!($data = json_decode(file_get_contents($file), true))) {
                        return false;
                }

                if (!array_key_exists($user, $data)) {
                        return false;
                }
                if (!($data[$user] == $pass)) {
                        return false;
                }

                return true;
        }

}

/**
 * Validate against tab-separated data.
 */
class FileValidatorTab implements FileValidatorBackend
{

        public function validate($file, $user, $pass, $handle = false)
        {
                if (filesize($file) == 0) {
                        return false;
                }

                try {
                        if (!($handle = fopen($file, "r"))) {
                                throw new Exception(sprintf("Failed open input file %s for reading in file validator.", $this->_file));
                        }

                        while (($line = fgets($handle))) {
                                $data = explode("\t", trim($line));
                                if (count($data) < 2) {
                                        throw new Exception(sprintf("Expected two columns of data in input file %s in file validator.", $this->_file));
                                } elseif ($data[0] == $user && $data[1] == $pass) {
                                        return true;
                                }
                        }
                } finally {
                        if ($handle && !fclose($handle)) {
                                throw new Exception(sprintf("Failed close input file %s in file validator.", $this->_file));
                        }
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
 * @property-write string $file The file path.
 * @property-write int $format The file format.
 * 
 * @author Anders Lövgren (QNET/BMC CompDept)
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
         * Constructor.
         * 
         * @param string $file The file path.
         * @param int $format File data format.
         */
        public function __construct($file = 'user.dat', $format = self::FORMAT_PHP)
        {
                $this->_file = $file;
                $this->_format = $format;
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
                                $validator = new FileValidatorSerialized();
                                break;
                        case self::FORMAT_JSON:
                                $validator = new FileValidatorJson();
                                break;
                        case self::FORMAT_TAB:
                                $validator = new FileValidatorTab();
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
