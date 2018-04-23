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
        $this->iv = substr(hash(self::HASH_ALGORITHM, $secretIv ?: $this->secretKey), 0, 16);
    }

    /**
     * Generate new random iv
     *
     * @return string
     */
    public function regenerateIV()
    {
        $strong = true;
        $secretIv = bin2hex(openssl_random_pseudo_bytes(32, $strong));
        $this->iv = substr(hash(self::HASH_ALGORITHM, $secretIv ?: $this->secretKey), 0, 16);

        return $this->iv;
    }

    /**
     * @param string $plainText
     * @param null $iv
     * @return string
     */
    public function encrypt($plainText, $iv = null)
    {
        if ($iv) {
            $this->iv = $iv;
        }
        $encrypted = openssl_encrypt($plainText, $this->cipherAlgorithm, $this->secretKey, 0, $this->iv);

        return $this->base64UrlEncode($encrypted);
    }

    /**
     * @param string $encrypted
     * @param null $iv
     * @return string
     */
    public function decrypt($encrypted, $iv = null)
    {
        if ($iv) {
            $this->iv = $iv;
        }
        $decrypted = openssl_decrypt(
            $this->base64UrlDecode($encrypted),
            $this->cipherAlgorithm,
            $this->secretKey,
            0,
            $this->iv
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
}
