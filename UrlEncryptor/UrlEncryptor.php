<?php

/*
 * UrlEncryptor file.
 *
 * (c) Ala Eddine Khefifi <alakhefifi@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nzo\UrlEncryptorBundle\UrlEncryptor;

/**
 * Class UrlEncryptor
 * @package Nzo\UrlEncryptorBundle\UrlEncryptor
 */
class UrlEncryptor
{
    const CIPHER_ALGORITHM = 'aes-256-ctr';
    const HASH_ALGORITHM = 'sha256';
    const LENGTH = 16;
    const LENGTH_HALF = 8;

    /**
     * @var string
     */
    private $secretKey;

    /**
     * @var string
     */
    private $iv;

    /**
     * @var string
     */
    private $cipherAlgorithm;

    /**
     * UrlEncryptor constructor.
     *
     * @param string $secretKey
     * @param string $secretIv
     * @param string $cipherAlgorithm
     *
     * @throws \Exception
     */
    public function __construct($secretKey = '', $secretIv = '', $cipherAlgorithm = '')
    {
        $this->cipherAlgorithm = $cipherAlgorithm ?: self::CIPHER_ALGORITHM;

        if (!in_array($this->cipherAlgorithm, openssl_get_cipher_methods(true))) {
            throw new \Exception("NzoUrlEncryptor:: - unknown cipher algorithm {$this->cipherAlgorithm}");
        }

        $this->secretKey = $secretKey;
        $this->iv = substr(hash(self::HASH_ALGORITHM, $secretIv ?: $this->secretKey), 0, self::LENGTH);
    }

    /**
     * Generate new random iv
     *
     * @return string
     */
    public function regenerateIV()
    {
        $strong = true;
        $secretIv = bin2hex(openssl_random_pseudo_bytes(8, $strong));
        $iv = substr(hash(self::HASH_ALGORITHM, $secretIv ?: $this->secretKey), 0, self::LENGTH);

        return  $iv;
    }

    /**
     * @param string $plainText
     * @param null $iv
     * @param null $salt
     * @return string
     */
    public function encrypt($plainText, $iv = null, $salt = null)
    {
        $i = $this->iv;
        if ($iv) {
            $i = $this->merge($this->iv, $iv);
        }

        if ($salt) {
            $i = substr(hash(self::HASH_ALGORITHM, $i.$salt), 0, self::LENGTH);
        }

        $encrypted = openssl_encrypt($plainText, $this->cipherAlgorithm, $this->secretKey, 0, $i);
        return $this->base64UrlEncode($encrypted);
    }

    /**
     * @param string $encrypted
     * @param null $iv
     * @param null $salt
     * @return string
     */
    public function decrypt($encrypted, $iv = null, $salt = null)
    {
        $i = $this->iv;
        if ($iv) {
            $i = $this->merge($this->iv, $iv);
        }

        if ($salt) {
            $i = substr(hash(self::HASH_ALGORITHM, $i.$salt), 0, self::LENGTH);
        }

        $decrypted = openssl_decrypt(
            $this->base64UrlDecode($encrypted),
            $this->cipherAlgorithm,
            $this->secretKey,
            0,
            $i
        );
        return trim($decrypted);
    }

    /**
     * @param string $data
     * @return string
     */
    private function base64UrlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * @param string $data
     * @return string
     */
    private function base64UrlDecode($data)
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }

    private function merge($str1, $str2){

        // Split both strings
        $str1 = str_split($str1, 1);
        $str2 = str_split($str2, 1);

        // Swap variables if string 1 is larger than string 2
        if (count($str1) >= count($str2))
            list($str1, $str2) = [$str2, $str1];

        // Append the shorter string to the longer string
        for($x=0; $x < count($str1); $x++)
            $str2[$x] .= $str1[$x];

        return substr(hash(self::HASH_ALGORITHM, implode('', $str2)) ,0, self::LENGTH);
    }
}
