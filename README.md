# SodiumDummies

## Authentication
    
### Symmetric
    
#### Sign

```php
$sodium = new SodiumDummies();
 
$aliceKeyPair   = $sodium->generateKeyPair('sign');
// custom key pair > $sodium->generateCustomKeyPair('Alice', 'sign');
 
$aliceSecretKey = $sodium->generateSecretKeyFromKeyPair($aliceKeyPair, 'sign');
$alicePublicKey = $sodium->generatePublicKeyFromKeyPair($aliceKeyPair, 'sign');
 
$msgSigned  = $sodium->signMessage("It's me, Alice!", $aliceSecretKey);
$msgDecrypt = $sodium->decryptSignedMessage($msgSigned, $alicePublicKey);
```

## Encryption

### Symmetric

```php
$sodium = new SodiumDummies();
 
$nonce = $sodium->getNonce();
$key   = $sodium->generateKeygen('secretbox');
//custom key > $sodium->generateCustomKey('Custom', 'secretbox');
 
$secretBox        = $sodium->createSecretBox('This is a secret message', $nonce, $key);
$secretBoxcontent = $sodium->openSecretBox($secretBox, $nonce, $key);
```

### Asymmetric

#### Anonymous

```php
$sodium = new SodiumDummies();
 
$aliceKeyPair   = $sodium->generateKeyPair();
// custom key pair > $sodium->generateCustomKeyPair('Alice', 'box');
 
$aliceSecretKey = $sodium->generateSecretKeyFromKeyPair($aliceKeyPair);
$alicePublicKey = $sodium->generatePublicKeyFromKeyPair($aliceKeyPair);
 
$anonymousMessageToAlice = $sodium->createBoxSeal('Anonymous messagsse', $alicePublicKey);
$decryptedMessage        = $sodium->openBoxSeal($anonymous_message_to_alice, $aliceKeyPair);
```

#### Authenticated

```php
$sodium = new SodiumDummies();
 
$aliceKeyPair   = $sodium->generateKeyPair();
// custom key pair > $sodium->generateCustomKeyPair('Alice', 'box');
 
$aliceSecretKey = $sodium->generateSecretKeyFromKeyPair($aliceKeyPair);
$alicePublicKey = $sodium->generatePublicKeyFromKeyPair($aliceKeyPair);
 
$bobKeyPair   = $sodium->generateKeyPair();
// custom key pair > $sodium->generateCustomKeyPair('Bob', 'box');
 
$bobSecretKey = $sodium->generateSecretKeyFromKeyPair($bobKeyPair);
$bobPublicKey = $sodium->generatePublicKeyFromKeyPair($bobKeyPair);
 
$aliceToBobKey = $sodium->getKeyFromSecretKeyAndPublicKey($aliceSecretKey, $bobPublicKey);
$bobToAliceKey = $sodium->getKeyFromSecretKeyAndPublicKey($bobSecretKey, $alicePublicKey);
 
$nonce = $sodium->getNonce();
 
$messageCrypted          = $sodium->createBox("Hello Bob/Alice", $nonce, $aliceToBobKey);
$messageDecryptedByBob   = $sodium->openBox($messageCrypted, $nonce, $bobToAliceKey);
$messageDecryptedByAlice = $sodium->openBox($messageCrypted, $nonce, $aliceToBobKey);
```