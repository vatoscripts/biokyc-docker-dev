@extends('layout.app')

@include('includes.registration.background')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">

            <div class="content-heading">
                <h3>SET PRIMARY NUMBER</h3>
            </div>

                <div class="row">
                    <!-- START dashboard main content-->
                    <div class="col-xl-12">
                        <!-- START chart-->
                        <!-- Button trigger modal -->
                        <blockquote id="error-message"></blockquote>
                        <div class="card b">
                            <div class="card-body">
                                <div id="AgentNIDA" class="modal-body p-3">
                                    <form method="post" action="{{ action('KYCController@postPrimarySIMFirstPage') }}" class="mb-3" id="PrimarySIMNIDAForm" >
                                        @csrf
                                        <div class="form-group">
                                            <label for="exampleInputEmail1" class="text-bold">NIDA Number</label>
                                            <input id="NIN" name="NIN" class="form-control" type="text" placeholder="Enter NIDA number">
                                        </div>
                                        <input type="hidden" name="fingerData" id="fingerData">
                                        <input type="hidden" name="fingerCode" id="fingerCode">
                                        <div id="Div_fingerprint" style="margin-block-end: 10px;"></div>

                                        <div class="modal-footer">
                                            <button id="oneSIMPrimarySubmitNIDA" type="submit" class="btn btn-primary"><span class="fa fa-save"></span> Proceed</button>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>

                    </div>
                    <!-- END dashboard main content-->
                </div>
        </div>

    </section>
@endsection

@section('scripts')

    <script src="{{ asset('js/vtlbio.js') }}"></script>

    <script>
        var x = new VTLBion();
        x.Init("Div_fingerprint");
    </script>

    <script src="{{ asset('js/one-sim/oneSIMPrimaryNIDA.js') }}"></script>

@endsection
