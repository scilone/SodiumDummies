<?php

/**
 * Class SodiumDummies
 */
class SodiumDummies
{
    /**
     * Generate a random key pair wich will allow create secret and public key
     *
     * @param string $type
     *
     * @throws Exception
     *
     * @return string
     */
    public function generateKeyPair(string $type = '') :string
    {
        switch ($type) {
            case 'kx':
                return sodium_crypto_kx_keypair();
            case 'sign':
                return sodium_crypto_sign_keypair();
            case 'box':
            case '':
                return sodium_crypto_box_keypair();
            default:
                throw new Exception('Unknown type');

        }
    }

    /**
     * Allow user to generate a key pair wich will allow create secret and public key
     *
     * @param string $text
     * @param string $type
     *
     * @throws Exception
     *
     * @return string
     */
    public function generateCustomKeyPair(string $text, string $type = '') :string
    {
        switch ($type) {
            case 'kx':
                return sodium_crypto_kx_seed_keypair(
                    sodium_crypto_generichash(
                        $text,
                        '',
                        SODIUM_CRYPTO_KX_BYTES
                    )
                );
            case 'sign':
                return sodium_crypto_sign_seed_keypair(
                    sodium_crypto_generichash(
                        $text,
                        '',
                        SODIUM_CRYPTO_SIGN_BYTES
                    )
                );
            case 'box':
            case '':
                return sodium_crypto_box_seed_keypair(
                    sodium_crypto_generichash(
                        $text,
                        '',
                        SODIUM_CRYPTO_AUTH_KEYBYTES
                    )
                );
            default:
                throw new Exception('Unknown type');

        }
    }

    /**
     * Generate a secret key thanks to key pair
     *
     * @param string $keyPair
     * @param string $type
     *
     * @throws Exception
     *
     * @return string
     */
    public function generateSecretKeyFromKeyPair(string $keyPair, string $type = '') :string
    {
        switch ($type) {
            case 'kx':
                return sodium_crypto_kx_secretkey($keyPair);
            case 'sign':
                return sodium_crypto_sign_secretkey($keyPair);
            case 'box':
            case '':
                return sodium_crypto_box_secretkey($keyPair);
            default:
                throw new Exception('Unknown type');

        }
    }

    /**
     * Generate a public key thanks to key pair
     *
     * @param string $keyPair
     * @param string $type
     *
     * @throws Exception
     *
     * @return string
     */
    public function generatePublicKeyFromKeyPair(string $keyPair, string $type = '') :string
    {
        switch ($type) {
            case 'kx':
                return sodium_crypto_kx_publickey($keyPair);
            case 'sign':
                return sodium_crypto_sign_publickey($keyPair);
            case 'box':
            case '':
                return sodium_crypto_box_publickey($keyPair);
            default:
                throw new Exception('Unknown type');

        }
    }

    /**
     * Create a key from secret and public key
     * This key must be confidential cause it contain a secret key, and can be used to encrypt or decrypt a message
     *
     * @param string $secretKey
     * @param string $publicKey
     * @param string $type
     *
     * @throws Exception
     *
     * @return string
     */
    public function getKeyFromSecretKeyAndPublicKey(string $secretKey, string $publicKey, $type = '') :string
    {
        switch ($type) {
            case 'sign':
                return sodium_crypto_sign_keypair_from_secretkey_and_publickey($secretKey, $publicKey);
            case 'box':
            case '':
                return sodium_crypto_box_keypair_from_secretkey_and_publickey($secretKey, $publicKey);
            default:
                throw new Exception('Unknown type');

        }
    }

    /**
     * @param string $type
     *
     * @throws Exception
     *
     * @return string
     */
    public function getNonce(string $type = '') :string
    {
        switch ($type) {
            case 'secretbox':
                return random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            case 'stream':
                return random_bytes(SODIUM_CRYPTO_STREAM_NONCEBYTES);
            case 'box':
            case '':
                return random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);
            default:
                throw new Exception('Unknown type');

        }
    }

    /**
     * Create a Box
     * A box is a crypt message which can be decrypted by 2 people
     * These 2 people are the public key owner and the private key owner that allowed to create the key
     *
     * @param string $text
     * @param string $nonce
     * @param string $key
     *
     * @return string
     */
    public function createBox(string $text, string $nonce, string $key) :string
    {
        return sodium_crypto_box($text, $nonce, $key);
    }

    /**
     * Open a closed box
     * A box is a crypt message which can be decrypted by 2 people
     * These 2 people are the public key owner and the private key owner that allowed to create the key
     *
     * @param string $textCrypted
     * @param string $nonce
     * @param string $key
     *
     * @return string
     */
    public function openBox(string $textCrypted, string $nonce, string $key) :string
    {
        return sodium_crypto_box_open($textCrypted, $nonce, $key);
    }

    /**
     * Create a box seal
     * A box seal is a crypt message which can only be decrypted by 1 person, public key owner
     *
     * @param string $text
     * @param string $publicKey
     *
     * @return string
     */
    public function createBoxSeal(string $text, string $publicKey) :string
    {
        return sodium_crypto_box_seal($text, $publicKey);
    }

    /**
     * Open a closed box seal
     * The private key owner are the only one who can open the box seal
     *
     * @param string $textCrypted
     * @param string $privateKey
     *
     * @return string
     */
    public function openBoxSeal(string $textCrypted, string $privateKey) :string
    {
        return sodium_crypto_box_seal_open($textCrypted, $privateKey);
    }
}