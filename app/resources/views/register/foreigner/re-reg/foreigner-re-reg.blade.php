@extends('layout.app')

@include('includes.registration.background')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">

            <div class="content-heading">
                <div>Foreigner Re-Registration
                    <p class="lead mt-2">KYC Details</p>
                </div>
            </div>

            @include('layout.flash-messages')

            <!-- START cards box-->
                <!-- END cards box-->
                <div class="row">
                    <!-- START dashboard main content-->
                    <div class="col-xl-12">
                        <blockquote id="flash-message" ></blockquote>
                        <div class="card b">
                            <div class="card-body">
                                <form method="post" action="{{ action('KYC\KYCController@recheckMSISDNIcap') }}" id="checkMSISDNIcapForm" novalidate>
                                    @csrf
                                    <div class="form-group">
                                        <div class="input-group with-focus mb-2">
                                            <input name="phoneNumber" class="form-control" id="exampleInputEmail1" type="text" placeholder="Enter Mobile Number e.g 0754000000" autocomplete="off" required>
                                            <div class="input-group-append">
                                                <button id="checkMsisdnIcapBtn" class="btn btn-block btn-info" type="submit">
                                                <span class="fa fa-search-plus"></span> Check Number</button>
                                            </div>
                                        </div>
                                    </div>
                                </form>
                            </div>
                        </div>

                    </div>
                    <!-- END dashboard main content-->
                </div>
        </div>

    </section>
@endsection

@section('scripts')

@include('register.foreigner.re-reg.foreigner-re-reg-modal')
@include('register.nida.total-mismatch')

<script src="{{ asset('js/vtlbio.js') }}"></script>

    <script>
        var x = new VTLBion();
        x.Init("Div_fingerprint");
    </script>

<script src="{{ asset('js/foreigner-re-reg.js') }}"></script>

@endsection

