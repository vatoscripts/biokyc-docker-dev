@extends('layout.app')

@section('title', 'Register Bulk Msisdn')

@include('includes.registration.background')

@section('content')

<section class="section-container">
    <!-- Page content-->
    <div class="content-wrapper">

        <div class="content-heading">
            <div>Bulk Registration
                {{-- <p class="lead mt-2">KYA Details: Agent recruitment.</p> --}}
            </div>
        </div>

        @include('layout.flash-messages')

        <div class="row">
            <!-- START dashboard main content-->
            <div class="col-xl-12">
                <!-- START chart-->
                <!-- Button trigger modal -->

                <div class="card b">
                    <div class="card-body">
                        <!---modal button-->
                        <button type="button" class="btn btn-dark float-right" data-target="#bulk-register-page1" data-toggle="modal">
                            <span class="fa fa-bars"></span> New Bulk Registration </button>
                        <!---modal button ends-->
                    </div>
                </div>

            </div>
            <!-- END dashboard main content-->
        </div>
    </div>

</section>
@endsection

@section('scripts')

@include('register.bulk-reg.bulk-modal-page1')
@include('register.bulk-reg.bulk-modal-page2')

<script src="{{ asset('js/vtlbio.js') }}"></script>

<script>
    var x = new VTLBion();
    x.Init("Div_fingerprint");
</script>

<script src="{{ asset('js/bulk-registration.js') }}"></script>

@endsection
