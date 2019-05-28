<?php
namespace Tappleby\AuthToken;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Support\Facades\Cache;

class CacheAuthTokenProvider extends AbstractAuthTokenProvider {

  /**
   * @param \Illuminate\Encryption\Encrypter $encrypter
   * @param \App\AuthToken\HashProvider $hasher
   */
  function __construct(Encrypter $encrypter, HashProvider $hasher)
  {
    parent::__construct($encrypter, $hasher);
  }

  /**
   * Creates an auth token for user.
   *
   * @param Illuminate\Contracts\Auth\Authenticatable $user
   * @param  Timeout duration in minutes. Default Value longSessionTimeout.
   * @return \App\AuthToken\AuthToken|false
   */
  public function create(Authenticatable $user, $minutes = null)
  {
    if($minutes == null){
      $minutes = $this->longSessionTimeout;
    }

    if($user == null || $user->getAuthIdentifier() == null) {
      return false;
    }

    $token = $this->generateAuthToken();
    $token->setAuthIdentifier( $user->getAuthIdentifier() );
   
    $t = new \DateTime;
   
    $key = $token->getPublicKey() . ':' . $token->getPrivateKey();
    Cache::tags(['AUTHTOKEN', $token->getAuthIdentifier()])
         ->put($key, $t, $minutes);
    return $token;
  }

  /**
   * Find user id from auth token.
   *
   * @param $serializedAuthToken string
   * @return \App\AuthToken\AuthToken|null
   */
  public function find($serializedAuthToken)
  {
    $authToken = $this->deserializeToken($serializedAuthToken);

    if($authToken == null) {
      return null;
    }

    if(!$this->verifyAuthToken($authToken)) {
      return null;
    }

    $key = $authToken->getPublicKey() . ':' . $authToken->getPrivateKey();
    if (!Cache::tags(['AUTHTOKEN', $authToken->getAuthIdentifier()])->has($key)){
       return null;
    }

    return $authToken;
  }

  /**
   * @param mixed|\Illuminate\Contracts\Auth\Authenticatable $identifier
   * @return bool
   */
  public function purge($identifier)
  {
    if($identifier instanceof Authenticatable) {
      $identifier = $identifier->getAuthIdentifier();
    }
    Cache::tags([$identifier])->flush();
    return true;
  }


  /**
   * Finds an auth token and deleted if exists
   * @param  $serializedAuthToken
   * @return bool True if existed and deleted the token otherwise false
   */
  public function delete($serializedAuthToken){
    $authToken = $this->deserializeToken($serializedAuthToken);

    if($authToken == null) {
      return false;
    }

    if(!$this->verifyAuthToken($authToken)) {
      return false;
    }

    $key = $authToken->getPublicKey() . ':' . $authToken->getPrivateKey();

    if (!Cache::tags(['AUTHTOKEN', $authToken->getAuthIdentifier()])->has($key)){
       return false;
    }
    Cache::tags(['AUTHTOKEN', $authToken->getAuthIdentifier()])->forget($key);
    return true;
  }
}