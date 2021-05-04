@extends('layout.app')

@include('includes.registration.background')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">

            <div class="content-heading">
                <h3>Select Number to set as primary
                    {{-- <p class="lead mt-2">Vivamus sagittis lacus luctus.</p> --}}
                </h3>
            </div>

                <div class="row">
                    <!-- START dashboard main content-->
                    <div class="col-xl-12">
                        <!-- START chart-->
                        <!-- Button trigger modal -->
                        @include('layout.flash-messages')
                        <div class="card b">
                            <div class="card-body">
                                <div id="AgentNIDA" class="modal-body p-3">
                                    <form method="post" action="{{ action('KYCController@setPrimaryMsisdnOther') }}" class="mb-3" id="setPrimaryMsisdnOtherForm" novalidate>
                                        @csrf
                                        <div class="form-group" >
                                            <label class="font-weight-bold mb-4" for="isADUser">List Customer MSISDN(s)</label>
                                            <input type="hidden" name="customerID" value="{{ $ID }}">
                                            <div class="form-row" id='primaryMSISDNList'>

                                                @foreach ($msisdn as  $node)
                                                    <div class="col-3">
                                                        <label class="radio-inline">
                                                        <input class="mr-2" type="radio" id="primaryMsisdn" name="primaryMsisdn" value="{{$node}}">{{$node}}</label>
                                                    </div>
                                                @endforeach
                                            </div>
                                        </div>

                                        <div class="modal-footer">
                                            <button id="setPrimaryMsisdnOtherBtn" type="submit" class="btn btn-primary"><span class="fa fa-save"></span> Confirm</button>
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

    <script src="{{ asset('js/one-sim/other/set-primary.js') }}"></script>

@endsection
