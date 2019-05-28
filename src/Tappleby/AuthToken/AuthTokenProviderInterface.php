<?php
/**
 * Created by IntelliJ IDEA.
 * User: tappleby
 * Date: 2013-05-11
 * Time: 2:53 PM
 * To change this template use File | Settings | File Templates.
 */

namespace Tappleby\AuthToken;


use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Class AuthTokenProviderInterface
 * @package App\AuthToken
 */
interface AuthTokenProviderInterface {


  /**
   * Creates an auth token for user.
   *
   * @param Illuminate\Contracts\Auth\Authenticatable $user
   * @param  Timeout duration in minutes. Default Value longSessionTimeout.
   * @return \App\AuthToken\AuthToken|false
   */
  public function create(Authenticatable $user, $minutes = null);


  /**
   * Find user id from auth token.
   *
   * @param $serializedAuthToken string
   * @return \App\AuthToken\AuthToken|null
   */
  public function find($serializedAuthToken);

  /**
   * Returns serialized token.
   *
   * @param AuthToken $token
   * @return string
   */
  public function serializeToken(AuthToken $token);

  /**
   * Deserializes token.
   *
   * @param string $payload
   * @return AuthToken
   */
  public function deserializeToken($payload);

  /**
   * @param mixed|\Illuminate\Contracts\Auth\Authenticatable $identifier
   * @return bool
   */
  public function purge($identifier);

  /**
   * Finds an auth token and deleted if exists
   * @param  $serializedAuthToken []
   * @return bool True if existed and deleted the token otherwise false
   */
  public function delete($serializedAuthToken);

  /**
   * Refresh an existing token given its payload
   * @param  User owner of the token 
   * @param  String $payload 
   * @param  Timeout duration in minutes. Default Value longSessionTimeout.
   * @return String new Serialized token
   */
  public function refreshToken(Authenticatable $user, $payload, $minutes = null);
}