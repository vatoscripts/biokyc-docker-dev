<!-- Stored in resources/views/child.blade.php -->

@extends('layout.auth')

@section('title', 'Page Title')

@section('sidebar')
    @parent

    <p>This is appended to the master sidebar.</p>
@endsection

@section('content')

<!-- START card-->
<div class="card card-flat">
    <div class="card-header text-center bg-dark">
        <a href="#">
            <img class="block-center rounded" src="img/logo.svg" width="190" height="60" alt="Image">
        </a>
    </div>

    @include('layout.flash-messages')

    <div class="card-body">
        <p class="text-center py-2">RESET PASSWORD</p>
        <hr size="5" type="dotted"></hr>
        <form method="post" action="{{ action('UserController@RecoverPassword') }}" class="mb-3" id="loginForm" novalidate>
            @csrf
            <div class="form-group">
                <div class="input-group with-focus">
                    <input class="form-control border-right-0" name="inputpwd1" type="password" placeholder="New Password" autocomplete="off" required>
                    <div class="input-group-append">
                        <span class="input-group-text text-muted bg-transparent border-left-0">
                          <em class="fa fa-lock"></em>
                       </span>
                    </div>
                </div>
            </div>
            <div class="form-group">
                <div class="input-group with-focus">
                    <input class="form-control border-right-0" name="inputpwd2" type="password" placeholder="Confirm Password" required>
                    <div class="input-group-append">
                        <span class="input-group-text text-muted bg-transparent border-left-0">
                          <em class="fa fa-lock"></em>
                       </span>
                    </div>
                </div>
            </div>

            <button class="btn btn-block btn-danger mt-3" type="submit">Save New Password</button>
            <div class="clearfix">

                <div class="float-right">
                    <a class="text-muted" href="recover.html">Back to login?</a>
                </div>
            </div>

        </form>

    </div>
</div>
<!-- END card-->
@endsection
