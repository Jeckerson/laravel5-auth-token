<?php
/*
 * User: tappleby
 * Date: 2013-05-11
 * Time: 9:23 PM
 */

namespace Tappleby\AuthToken;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Tappleby\AuthToken\Exceptions\NotAuthorizedException;

class AuthTokenDriver {
  /**
   * @var \Tappleby\AuthToken\AuthTokenProviderInterface
   */
  protected $tokens;

  /**
   * @var Illuminate\Contracts\Auth\UserProvider
   */
  protected $users;

  function __construct(AuthTokenProviderInterface $tokens, UserProvider $users)
  {
    $this->tokens = $tokens;
    $this->users = $users;
  }

  /**
   * Returns the AuthTokenInterface provider.
   *
   * @return \Tappleby\AuthToken\AuthTokenProviderInterface
   */
  public function getProvider()
  {
    return $this->tokens;
  }


  /**
   * Validates a public auth token. Returns User object on success, otherwise false.
   *
   * @param $authTokenPayload
   * @return bool|Authenticatable
   */
  public function validate($authTokenPayload) {

    if($authTokenPayload == null) {
      return false;
    }

    $tokenResponse = $this->tokens->find($authTokenPayload);

    if($tokenResponse == null) {
      return false;
    }

    $user = $this->users->retrieveByID( $tokenResponse->getAuthIdentifier() );

    if($user == null) {
      return false;
    }

    return $user;
  }

  /**
   * Attempt to create an AuthToken from user credentials.
   *
   * @param array $credentials
   * @return bool|AuthToken
   */
  public function attempt(array $credentials) {
    $user = $this->users->retrieveByCredentials($credentials);

    if($user instanceof Authenticatable && $this->users->validateCredentials($user, $credentials)) {
       return $this->create($user);
    }

    return false;
  }

  /**
   * Create auth token for user.
   *
   * @param Authenticatable $user
   * @return bool|AuthToken
   */
  public function create(Authenticatable $user) {
    return $this->tokens->create($user);
  }

  /**
   * Retrive user from auth token.
   *
   * @param AuthToken $token
   * @return Authenticatable|null
   */
  public function user(AuthToken $token) {
    return $this->users->retrieveByID( $token->getAuthIdentifier() );
  }

  /**
   * Removes all the tokens of an user.
   *
   * @param Authenticatable $user
   * @return bool
   */
  public function purge(Authenticatable $user) {
    return $this->tokens->purge($user);
  }

  /**
   * Serialize token for public use.
   *
   * @param AuthToken $token
   * @return string
   */
  public function publicToken(AuthToken $token) {
    return $this->tokens->serializeToken($token);
  }
}