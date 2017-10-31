<?php

    /**
     * @name   php加密解密类
     * @author 岁月神偷
     * @email  systom@sina.cn
     * @date   2017-10-31
     */
    class Zoeey {

        const OBFUSCATED_ORDER = array(
            13,  6,  5,  7,  1, 15, 14, 20
        ,  9, 16, 19,  4, 18, 10,  2,  8
        , 12,  3, 11,  0, 17
        );
        const ORDER_SIZE = 21;

        const OBFUSCATED_ALPHABET = array(
            's', '4', 'N', 'E', 'k', 'X', 'c', 'u'
        , 'J', '2', 'U', 'o', 'O', 'w', 'K', 'v'
        , 'h', 'H', 'C', '/', 'D', 'q', 'l', 'R'
        , 'B', 'r', '5', 'Z', 'S', 'Q', '6', 'W'
        , '3', 'L', 'j', '8', '1', 'z', '0', 'G'
        , 'n', 'e', 'y', 'b', 'I', 'd', 'i', 'P'
        , 'A', '9', '7', '+', 'm', 'V', 'M', 'Y'
        , 'F', 'g', 'f', 'p', 'a', 'T', 't', 'x'
        );
        const ALPHABET_SIZE = 64;
        private $alphabet_bytes = array();
        private function get_alphabet_bytes()
        {
            for ($i = 0; $i < static::ALPHABET_SIZE; $i++) {
                $this->alphabet_bytes[static::OBFUSCATED_ALPHABET[$i]] = $i;
            }
        }
        /**
         * @name 解密密文
         * @param String $ciphertext   密文
         * @param String $key          秘钥
         * @return string
         */
        public function decode($ciphertext,$key)
        {
            $key_len = strlen($key);
            $this->get_alphabet_bytes();
            //  计算密文长度
            $eq_len = strlen($ciphertext);
            $equal_count = 1;
            $enc = $this->substr_n($ciphertext, strlen($ciphertext), 0,$eq_len - $equal_count);
            $eq_len = strlen($ciphertext);
            $enc_len = $eq_len;
            $enc_idx=0;
            $code_idx = 0;
            $code_len = (($eq_len * 3) / 4) - $equal_count;
            $code = str_pad("",$code_len," ");
            $idx = 0;
            while ($idx < $enc_len) {
                if ($code_idx == $code_len) {
                    break;
                }
                $pre = @ord($ciphertext[$enc_idx]) & 0xFF;
                $pre = @$this->alphabet_bytes[chr($pre)];
                $enc_idx++;
                $suf = @ord($ciphertext[$enc_idx]) & 0xFF;
                $suf = @$this->alphabet_bytes[chr($suf)];
                $pos = $idx + 1;
                if ($pos % 3 == 1) {
                    $pos = 1;
                } else if ($pos % 3 == 2) {
                    $pos = 2;
                } else {
                    $pos = 3;
                }
                switch ($pos) {
                    case 1:
                        $ch = ((($pre << 2) & 0xFC) | (($suf >> 4) & 3));
                        break;
                    case 2:
                        $ch = ((($pre << 4) & 0xF0) | (($suf >> 2) & 0xF));
                        break;
                    case 3:
                        $ch = ((($pre << 6) & 0xC0) | ($suf & 0x3F));;
                        break;
                }
                if($ch > 127)
                {
                    $ch = $ch - 256;
                }
                $code[$code_idx] = chr($ch);
                $code_idx++;
                if ($enc_idx == $enc_len) {
                    break;
                }
        
                if (($idx + 1) % 3 == 0) {
                    $enc_idx++;
                }
                $idx++;
            }
            $code_len = $idx;
            $swaped_key = str_pad("",$key_len," ");
            $source = str_pad("",$code_len," ");
            $this->swap_by_order($key,$swaped_key,$key_len);
            $key_idx = 0;
            for ($i = 0; $i < $code_len; $i++, $key_idx++) {
                if ($key_idx == $key_len) {
                    $key_idx = 0;
                }
                $code[$i] = $code[$i] ^ $key[$key_idx];
                $code[$i] = $code[$i] ^ $swaped_key[$key_idx];
            }
            $this->deswap_by_order($code,$source,$code_len);
            return $source;
        }

        /**
         * @name  加密原文
         * @param $code    需要加密的原文
         * @param $key     秘钥
         * @return string
         */
        public function encode($code,$key)
        {
            $code_len = strlen($code);
            $key_len = strlen($key);
            $swaped_key = array();
            $this->swap_by_order($key, $swaped_key, $key_len);
            // swap code
            $swaped_code = array();
            $this->swap_by_order($code, $swaped_code, $code_len);
            $key_idx = 0;
            $i = 0;
            $x_code = $code;
            for ($i = 0; $i < $code_len; $i++, $key_idx++) {
                if ($key_idx == $key_len) {
                    $key_idx = 0;
                }
                @$x_code[$i] = $swaped_code[$i] ^ $key[$key_idx];
                $x_code[$i] = $x_code[$i]^ $swaped_key[$key_idx];
            }
            $idx = 0;
            $j = 0;
            $based_code_len = ($code_len + 3) * 4 / 3;
            $base_code = str_pad("",$based_code_len," ");
            $base_idx = 0;
            while ($idx < $code_len) {
                for ($i = 0; $i < 3; $i++) {
                    $idx++;
                    $chs[$i] = $x_code[$idx - 1];
                    if ($idx == $code_len) {
                        break;
                    }
                }
                $i++;
                if ($i > 0) {
                    $base_code[$base_idx] = static::OBFUSCATED_ALPHABET[(ord($chs[0]) >> 2) & 0x3F];
                    $base_idx++;
                    $base_code[$base_idx] = static::OBFUSCATED_ALPHABET[(((ord($chs[0]) & 3) << 4) & 0x30) + ((ord($chs[1]) >> 4) & 0xF)];
                    $base_idx++;
                }
                if ($i > 1) {
                    $base_code[$base_idx] = static::OBFUSCATED_ALPHABET[(((ord($chs[1]) & 15) << 2) & 0x3C) + ((ord($chs[2]) >> 6) & 0x3)];
                    $base_idx++;
                }
                if ($i > 2) {
                    $base_code[$base_idx] = static::OBFUSCATED_ALPHABET[ord($chs[2]) & 0x3F];
                    $base_idx++;
                }
                for ($j = $i; $j < 3; $j++) {
                    $base_code[$base_idx] = '=';
                    $base_idx++;
                }
            }
            $base_code = substr($base_code,0,$base_idx);
            $base_idx++;
            return $base_code;
        }

        /**
         * @param $source
         * @param $len
         * @param $offset
         * @param $size
         * @return string
         */
        private function substr_n($source,$len,$offset,$size)
        {
            $j = 0;
            $i = $offset;
            $sub_len = $size > 0 ? $size : $len - $offset;
            $sub = str_pad("",$sub_len," ");
            while ($i < $len) {
                if ($i >= $offset) {
                    @$sub[$j] = $source[$i];
                    $j++;
                    if ($size != 0 && $j == $size) {
                        break;
                    }
                }
                $i++;
            }
            return $sub;
        }

        /**
         * @param $str
         * @param $swaped
         * @param $str_len
         */
        private function swap_by_order($str,&$swaped,$str_len)
        {
            $order_len = static::ORDER_SIZE;
            $last_len = $str_len % $order_len;
            $pre_str_len = $str_len - $last_len;
            $last = $this->substr_n($str, $str_len, $pre_str_len,0);
            $offset = 0;
            if ($pre_str_len > 0) {

                for ($i = 0; $i < $pre_str_len; $i++) {
                    $pos = ($i - $i % $order_len) + static::OBFUSCATED_ORDER[$i % $order_len];
                    @$swaped[$i] = $str[$pos % $pre_str_len];
                }
                $offset = $i;
            }
            if ($last_len > 0) {
                $last_order = array();
                $j = 0;
                for ($i = 0; $i < $order_len; $i++) {
                    if (static::OBFUSCATED_ORDER[$i] < $last_len) {
                        $last_order[$j] = static::OBFUSCATED_ORDER[$i];
                        $j++;
                        if ($j == $last_len) {
                            break;
                        }
                    }
                }

                for ($i = 0; $i < $last_len; $i++) {
                    $pos = $last_order[$i % $last_len];
                    $swaped[$i + $offset] = $last[$pos % $last_len];
                }
            }
        }

        /**
         * @param $str
         * @param $deswaped
         * @param $str_len
         */
        private function deswap_by_order($str,&$deswaped,$str_len)
        {
            $order_len = static::ORDER_SIZE;
            $pos = 0;
            $last_len = $str_len % $order_len;
            $pre_str_len = $str_len - $last_len;
            $last = $this->substr_n($str, $str_len, $pre_str_len,0);
            $offset = 0;
            for ($i = 0; $i < static::ORDER_SIZE; $i++) {
                $order_bytes[static::OBFUSCATED_ORDER[$i]] = $i;
            }
            if ($pre_str_len > 0) {
                for ($i = 0; $i < $pre_str_len; $i++) {
                    $pos = $i - $i % $order_len + $order_bytes[$i % $order_len ];
                    $deswaped[$i] = $str[$pos];
                }
                $offset = $i;
            }
            if ($last_len > 0) {
                $last_order = array();
                $j = 0;
                for ($i = 0; $i < $order_len; $i++) {
                    if (static::OBFUSCATED_ORDER[$i] < $last_len) {
                        $last_order[$j] = static::OBFUSCATED_ORDER[$i];
                        $j++;
                        if ($j == $last_len) {
                            break;
                        }
                    }
                }
                $last_order_bytes = array();
                for ($i = 0; $i < $last_len; $i++) {
                    $last_order_bytes[$last_order[$i]] = $i;
                }
                for ($i = 0; $i < $last_len; $i++) {
                    $pos = $last_order_bytes[$i];
                    $deswaped[$offset + $i] = $last[$pos % $last_len];
                }
            }
        }
    }


    $php = '<?php echo 11; ?>';
    $code_len = strlen($php);
    $code = (new Zoeey())->encode($php,"123456789");
    echo '加密后代码: |',$code,"|\n";
    $code = (new Zoeey())->decode($code,"123456789");
    echo '解密后代码: |',$code,"|\n";
