@extends('layout.app')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">

            <div class="content-heading">
                <div>Customer Registration Details
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
                                <form method="post" action="{{ action('Support\KYCSupportController@getCustomerRegDetails') }}" id="searchStaffAccountDetailssForm" novalidate>
                                    @csrf

                                        <div class="form-group col-md-6 col-xs-12">
                                            <label for=""><strong>START DATE</strong></label>
                                            <input type="text" name="startDate" class="form-control" placeholder="Enter Start Date in YYYY-MM-DD">
                                        </div>

                                        <div class="form-group col-md-6 col-xs-12">
                                            <label for=""><strong>END DATE</strong></label>
                                            <input type="text" name="endDate" class="form-control" placeholder="Enter Start Date in YYYY-DD-MM">
                                        </div>

                                        <div class="form-group col-md-6 col-xs-12">
                                            <label for=""><strong>MSISDN</strong></label>
                                            <input name="msisdn" class="form-control" id="exampleInputEmail1" type="text" placeholder="Enter msisdn e.g 0754000000" autocomplete="off" required>
                                        </div>

                                        <div class="form-group col-md-6 col-xs-12">
                                            <label for="blockReason"><strong>REPORT TYPE</strong></label>
                                            <select class="custom-select" id="reportType" name="reportType">
                                                <option value="1">Registration Details</option>
                                                <option value="2">Historical Report</option>
                                            </select>
                                        </div>


                                        <div class="form-group col-6">
                                            <button id="searchCutomerDetailsBtn" class="btn btn-lg btn-block btn-outline-danger text-bold mt-4" type="submit">
                                            <span class="fa fa-search-plus"></span> Search Customer</button>
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

    <script src="{{ asset('js/customer-reg-details.js') }}"></script>

@endsection
