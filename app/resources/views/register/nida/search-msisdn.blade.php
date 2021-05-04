@extends('layout.app')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">

            <div class="content-heading">
                <div>Search Customer MSISDN
                    <p class="lead mt-2">KYC Details</p>
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
                                <form method="post" action="{{ action('KYCController@getCustomerDetails') }}" id="searchMsisdnDetailsForm" novalidate>
                                    @csrf
                                    <div class="form-group">
                                        <div class="input-group with-focus mb-2">
                                            <input name="phoneNumber" class="form-control" id="exampleInputEmail1" type="text" placeholder="Enter Mobile Number e.g 0754000000" autocomplete="off" required>
                                            <div class="input-group-append">
                                                <button id="searchMsisdnDetailsBtn" class="btn btn-block btn-info" type="submit">
                                                <span class="fa fa-search-plus"></span> Search Number</button>
                                            </div>
                                        </div>
                                    </div>
                                </form>
                            </div>
                        </div>

                    </div>
                    <!-- END dashboard main content-->
                </div>

                <div class="row" id="customer-details">
                </div>


        </div>

    </section>
@endsection

@section('scripts')

    @include('register.new-modal')

    <script src="{{ asset('js/customer-search.js') }}"></script>

@endsection
