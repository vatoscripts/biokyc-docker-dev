<?php

namespace App\Rules;

use Illuminate\Contracts\Validation\Rule;

class MinorDob implements Rule
{
    /**
     * Create a new rule instance.
     *
     * @return void
     */
    public function __construct()
    {
        //
    }

    /**
     * Determine if the validation rule passes.
     *
     * @param  string  $attribute
     * @param  mixed  $value
     * @return bool
     */
    public function passes($attribute, $value)
    {
        $dob = date('Y-m-d', strtotime(substr($value, 0, strpos($value, '('))));

        return $value >= 1896 && $value <= date('Y') && $value % 4 == 0;
    }

    /**
     * Get the validation error message.
     *
     * @return string
     */
    public function message()
    {
        return 'The validation error message.';
    }
}
