@extends('layout.app')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">

            <div class="content-heading">
                <div>Search User Details
                    <p class="lead mt-2">User Details</p>
                </div>
            </div>

            @include('layout.flash-messages')

            <!-- START cards box-->
                <!-- END cards box-->
                <div class="row">
                    <!-- START dashboard main content-->
                    <div class="col-xl-12">
                        {{-- <div id="error-message" class="align-center"></div> --}}
                        <blockquote id="flash-message" ></blockquote>
                        <div class="card b">
                            <div class="card-body">
                                <form method="post" action="{{ action('Support\KYASupportController@getUserDetails') }}" id="searchUserDetailssForm" novalidate>
                                    @csrf
                                    <div class="form-group">
                                        <div class="input-group with-focus mb-2">
                                            <input name="username" class="form-control" id="exampleInputEmail1" type="text" placeholder="Enter Username e.g 255754000000" autocomplete="off" required>
                                            <div class="input-group-append">
                                                <button id="searchUserDetailsBtn" class="btn btn-block btn-info" type="submit">
                                                <span class="fa fa-search-plus"></span> Search User</button>
                                            </div>
                                        </div>
                                    </div>
                                </form>
                            </div>
                        </div>

                    </div>
                    <!-- END dashboard main content-->
                </div>

                <div class="row" id="user-details"></div>
                <div class="row" id="user-manage-btn"></div>
                @if (session::get('status') == 'N')
                    <h1>TEST</h1>
                @endif
        </div>

    </section>
@endsection

@section('scripts')

    <script src="{{ asset('js/user-management.js') }}"></script>

@endsection
