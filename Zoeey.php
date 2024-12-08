<?php

class ZoeeyGuard {
    // 私钥
    private const PRIVATE_KEY = "28dsa7dsas12312389uy7aydh8h1h2i312";
    
    // 字符重排序数组
    private const OBFUSCATED_ORDER = [
        13, 6, 5, 7, 1, 15, 14, 20,
        9, 16, 19, 4, 18, 10, 2, 8,
        12, 3, 11, 0, 17
    ];

    // Base64字母表
    private const OBFUSCATED_ALPHABET = [
        's', '4', 'N', 'E', 'k', 'X', 'c', 'u',
        'J', '2', 'U', 'o', 'O', 'w', 'K', 'v',
        'h', 'H', 'C', '/', 'D', 'q', 'l', 'R',
        'B', 'r', '5', 'Z', 'S', 'Q', '6', 'W',
        '3', 'L', 'j', '8', '1', 'z', '0', 'G',
        'n', 'e', 'y', 'b', 'I', 'd', 'i', 'P',
        'A', '9', '7', '+', 'm', 'V', 'M', 'Y',
        'F', 'g', 'f', 'p', 'a', 'T', 't', 'x'
    ];

    // 加密方法
    public static function encode($code) {
        $keyLen = strlen(self::PRIVATE_KEY);
        $codeLen = strlen($code);
        
        // 字符重排序
        $swappedCode = self::swapByOrder($code);
        $swappedKey = self::swapByOrder(self::PRIVATE_KEY);
        
        // XOR加密
        $xCode = '';
        for($i = 0; $i < $codeLen; $i++) {
            $keyIdx = $i % $keyLen;
            $xCode .= chr(
                ord($swappedCode[$i]) ^ ord(self::PRIVATE_KEY[$keyIdx]) ^ 
                ord($swappedKey[$keyIdx])
            );
        }
        
        // Base64编码
        return self::base64Encode($xCode);
    }

    // 解密方法 
    public static function decode($ciphertext) {
        $keyLen = strlen(self::PRIVATE_KEY);
        
        // Base64解码
        $code = self::base64Decode($ciphertext);
        $codeLen = strlen($code);
        
        // 生成交换后的密钥
        $swappedKey = self::swapByOrder(self::PRIVATE_KEY);
        
        // XOR解密
        $decodedCode = '';
        for($i = 0; $i < $codeLen; $i++) {
            $keyIdx = $i % $keyLen;
            $decodedCode .= chr(
                ord($code[$i]) ^ ord(self::PRIVATE_KEY[$keyIdx]) ^ 
                ord($swappedKey[$keyIdx])
            );
        }
        
        // 还原字符顺序
        return self::deswapByOrder($decodedCode);
    }

    // 字符重排序
    private static function swapByOrder($str) {
        $strLen = strlen($str);
        $orderLen = count(self::OBFUSCATED_ORDER);
        
        $lastLen = $strLen % $orderLen;
        $preStrLen = $strLen - $lastLen;
        
        $swapped = '';
        
        // 处理主要部分
        if($preStrLen > 0) {
            for($i = 0; $i < $preStrLen; $i++) {
                $pos = ($i - ($i % $orderLen)) + self::OBFUSCATED_ORDER[$i % $orderLen];
                $swapped .= $str[$pos % $preStrLen];
            }
        }
        
        // 处理剩余部分
        if($lastLen > 0) {
            $last = substr($str, $preStrLen);
            $lastOrder = [];
            
            for($i = 0; $i < $orderLen && count($lastOrder) < $lastLen; $i++) {
                if(self::OBFUSCATED_ORDER[$i] < $lastLen) {
                    $lastOrder[] = self::OBFUSCATED_ORDER[$i];
                }
            }
            
            for($i = 0; $i < $lastLen; $i++) {
                $pos = $lastOrder[$i % $lastLen];
                $swapped .= $last[$pos % $lastLen];
            }
        }
        
        return $swapped;
    }

    // 还原字符顺序
    private static function deswapByOrder($str) {
        $strLen = strlen($str);
        $orderLen = count(self::OBFUSCATED_ORDER);
        
        $lastLen = $strLen % $orderLen;
        $preStrLen = $strLen - $lastLen;
        
        $deswapped = '';
        
        // 生成顺序映射
        $orderBytes = array_fill(0, $orderLen, 0);
        foreach(self::OBFUSCATED_ORDER as $i => $val) {
            $orderBytes[$val] = $i;
        }
        
        // 处理主要部分
        if($preStrLen > 0) {
            for($i = 0; $i < $preStrLen; $i++) {
                $pos = $i - ($i % $orderLen) + $orderBytes[$i % $orderLen];
                $deswapped .= $str[$pos];
            }
        }
        
        // 处理剩余部分
        if($lastLen > 0) {
            $last = substr($str, $preStrLen);
            $lastOrder = [];
            $lastOrderBytes = array_fill(0, $lastLen, 0);
            
            for($i = 0; $i < $orderLen && count($lastOrder) < $lastLen; $i++) {
                if(self::OBFUSCATED_ORDER[$i] < $lastLen) {
                    $lastOrder[] = self::OBFUSCATED_ORDER[$i];
                }
            }
            
            for($i = 0; $i < $lastLen; $i++) {
                $lastOrderBytes[$lastOrder[$i]] = $i;
            }
            
            for($i = 0; $i < $lastLen; $i++) {
                $pos = $lastOrderBytes[$i];
                $deswapped .= $last[$pos % $lastLen];
            }
        }
        
        return $deswapped;
    }

    // 自定义Base64编码
    private static function base64Encode($data) {
        $result = '';
        $length = strlen($data);
        $padding = $length % 3;
        
        for($i = 0; $i < $length; $i += 3) {
            $chunk = substr($data, $i, 3);
            $b = unpack('C*', $chunk);
            
            $b1 = ($b[1] ?? 0) >> 2;
            $b2 = (($b[1] ?? 0) & 0x03) << 4 | (($b[2] ?? 0) >> 4);
            $b3 = (($b[2] ?? 0) & 0x0F) << 2 | (($b[3] ?? 0) >> 6);
            $b4 = ($b[3] ?? 0) & 0x3F;
            
            $result .= self::OBFUSCATED_ALPHABET[$b1];
            $result .= self::OBFUSCATED_ALPHABET[$b2];
            
            if(isset($b[2])) {
                $result .= self::OBFUSCATED_ALPHABET[$b3];
            } else {
                $result .= '=';
            }
            
            if(isset($b[3])) {
                $result .= self::OBFUSCATED_ALPHABET[$b4];
            } else {
                $result .= '=';
            }
        }
        
        return $result;
    }

    // 自定义Base64解码
    private static function base64Decode($data) {
        // 创建反查表
        $revAlphabet = array_flip(self::OBFUSCATED_ALPHABET);
        
        // 移除padding
        $data = rtrim($data, '=');
        $length = strlen($data);
        $result = '';
        
        for($i = 0; $i < $length; $i += 4) {
            $b1 = $revAlphabet[$data[$i]];
            $b2 = $revAlphabet[$data[$i + 1] ?? '='];
            $b3 = isset($data[$i + 2]) ? $revAlphabet[$data[$i + 2]] : 0;
            $b4 = isset($data[$i + 3]) ? $revAlphabet[$data[$i + 3]] : 0;
            
            $c1 = ($b1 << 2) | ($b2 >> 4);
            $c2 = (($b2 & 0x0F) << 4) | ($b3 >> 2);
            $c3 = (($b3 & 0x03) << 6) | $b4;
            
            $result .= chr($c1);
            if($data[$i + 2] ?? '=' !== '=') {
                $result .= chr($c2);
            }
            if($data[$i + 3] ?? '=' !== '=') {
                $result .= chr($c3);
            }
        }
        
        return $result;
    }
}


// 加密
$encrypted = ZoeeyGuard::encode("test_string_original");
echo $encrypted,PHP_EOL; // 输出加密后的字符串

// 解密
$decrypted = ZoeeyGuard::decode($encrypted);
echo $decrypted,PHP_EOL; // 输出: test_string_original
