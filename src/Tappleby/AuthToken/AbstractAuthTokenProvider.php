<?php
/*
 * User: tappleby
 * Date: 2013-05-11
 * Time: 4:01 PM
 */

namespace Tappleby\AuthToken;


use Illuminate\Encryption\DecryptException;
use Illuminate\Encryption\Encrypter;
use Illuminate\Contracts\Auth\Authenticatable;

abstract class AbstractAuthTokenProvider implements AuthTokenProviderInterface {

  /**
   * @var \Illuminate\Encryption\Encrypter
   */
  protected $encrypter;

  /**
   * @var \Tappleby\AuthToken\HashProvider
   */
  protected $hasher;

  /**
   * Duration in minutes of a long session token
   * @var integer
   */
  protected $longSessionTimeout;

  /**
   * @return \Tappleby\AuthToken\HashProvider
   */
  public function getHasher()
  {
    return $this->hasher;
  }

  /**
   * @param Encrypter $encrypter
   * @param HashProvider $hasher
   */
  function __construct(Encrypter $encrypter, HashProvider $hasher)
  {
    $this->longSessionTimeout = 216000;
    $this->encrypter = $encrypter;
    $this->hasher = $hasher;
  }

  protected  function generateAuthToken($publicKey = null)
  {
    if(empty($publicKey)) {
      $publicKey = $this->hasher->make();
    }

    $privateKey = $this->hasher->makePrivate($publicKey);

    return new AuthToken(null, $publicKey, $privateKey);
  }

  protected function verifyAuthToken(AuthToken $token) {
    return $this->hasher->check($token->getPublicKey(), $token->getPrivateKey());
  }

  /**
   * Returns serialized token.
   *
   * @param AuthToken $token
   * @return string
   */
  public function serializeToken(AuthToken $token)
  {
    $payload = $this->encrypter->encrypt(array(
      'id' => $token->getAuthIdentifier(),
      'key' => $token->getPublicKey())
    );

		$payload = str_replace(array('+', '/', '\r', '\n', '='), array('-', '_'), $payload);

    return $payload;
  }

  /**
   * Deserializes token.
   *
   * @param string $payload
   * @return AuthToken|null
   */
  public function deserializeToken($payload)
  {
    try {
      $payload = str_replace(array('-', '_'), array('+', '/'), $payload);
      $data = $this->encrypter->decrypt($payload);
    } catch (DecryptException $e) {
      return null;
    }

    if(empty($data['id']) || empty($data['key'])) {
      return null;
    }

    $token = $this->generateAuthToken($data['key']);
    $token->setAuthIdentifier($data['id']);

    return $token;
  }

  /**
   * Refresh an existing token given its payload
   * @param  User owner of the token 
   * @param  String $payload 
   * @param  Timeout duration in minutes. Default Value LONG_SESSION_DURATION.
   * @return String new Serialized token
   */
  public function refreshToken(Authenticatable $user, $payload, $minutes = null){
    if($this->delete($payload)){
      $token = $this->create($user, $minutes);
      return $this->serializeToken($token);
    }
    return null;
  }
}