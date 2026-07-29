<?php

use Illuminate\Http\Request;

if (! function_exists('config')) {
    function config(string|array|null $key = null, mixed $default = null): mixed {}
}

if (! function_exists('config_path')) {
    function config_path(string $path = ''): string {}
}

if (! function_exists('request')) {
    function request(): Request {}
}
