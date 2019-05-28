<?php

namespace Tappleby\AuthToken;

use Closure;
use Illuminate\Events\Dispatcher;
use Tappleby\AuthToken\Exceptions\NotAuthorizedException;
use Auth;
use Input;

class AuthTokenMiddleware
{

    /**
     * The event dispatcher instance.
     *
     * @var \Illuminate\Events\Dispatcher
     */
    protected $events;

    /**
     * @var \App\AuthToken\AuthTokenDriver
     */
    protected $driver;

    function __construct(AuthTokenDriver $driver, Dispatcher $events)
    {
        $this->driver = $driver;
        $this->events = $events;
    }


    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure $next
     * @return mixed
     * @throws NotAuthorizedException
     */
    public function handle($request, Closure $next)
    {
        $payload = $request->header('X-Auth-Token');
        if (empty($payload)) {
            $payload = Input::get('auth_token');
        }

        $user = $this->driver->validate($payload);
        if (!$user) {
            throw new NotAuthorizedException();
        }

        Auth::setUser($user);
        $this->events->fire('auth.token.valid', $user);
        return $next($request);
    }

}