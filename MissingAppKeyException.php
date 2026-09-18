<?php

namespace Voyager\Encryption;

use RuntimeException;

class MissingAppKeyException extends RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $message
     */
    public function __construct(string $message = 'No application encryption key has been specified.')
    {
        parent::__construct($message);
    }
}
