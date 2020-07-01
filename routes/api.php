<?php

/** @var \Laravel\Lumen\Routing\Router $router */

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It is a breeze. Simply tell Lumen the URIs it should respond to
| and give it the Closure to call when that URI is requested.
|
*/

$router->post('/auth/login', [
    'as' => 'login',
    'uses' => 'Auth\AuthController@login'
]);

$router->group([
    'prefix' => 'auth',
    'middleware' => 'JSONWebToken'
], function () use ($router) {
    $router->get('/', function () use ($router) {
        return 'OK Sukses';
    });
});

