@extends('layout.app')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">

            <div class="content-heading">
                <div>Set Secondary Msisdn(Other)
                    <p class="lead mt-2">Secondary Msisdn</p>
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
                                <form method="post" action="{{ action('KYCController@getListSecondaryMsisdnOther') }}" id="searchSecondaryMsisdnListForm" novalidate>
                                    @csrf
                                    <div class="form-group">
                                        <div class="input-group with-focus mb-2">
                                            <input name="customerID" class="form-control" type="text" placeholder="Enter Customer ID number e.g AB123456">
                                            <div class="input-group-append">
                                                <button id="searchSecondaryMsisdnListBtn" class="btn btn-block btn-info" type="submit">
                                                <span class="fa fa-search-plus"></span> Check</button>
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

    <script src="{{ asset('js/one-sim/other/search-secondary-list.js') }}"></script>

@endsection
