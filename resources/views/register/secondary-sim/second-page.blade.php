@extends('layout.app')

@include('includes.registration.background')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">

            <div class="content-heading">
                <h3>Select Number to set as Secondary</h3>
            </div>

                <div class="row">
                    <!-- START dashboard main content-->
                    <div class="col-xl-12">
                        <!-- START chart-->
                        <!-- Button trigger modal -->
                        @include('layout.flash-messages')

                        <blockquote id="error-message"></blockquote>

                        <div class="card b">
                            <div class="card-body">
                                <div id="AgentNIDA" class="modal-body p-3">
                                    <form method="post" action="{{ action('KYCController@postSecondarySIMSecondPage') }}" class="mb-3" id="SecondarySIMTCRAForm" novalidate>
                                        @csrf

                                        <input type="hidden" name="ID" value="{{ $ID }}">
                                        <input type="hidden" name="NIN" value="{{ $NIN }}">
                                        <input type="hidden" name="Code" value="{{ $Code }}">

                                        <div class="form-group">
                                            <label class="font-weight-bold mb-4">Select Customer number </label>
                                            <div class="form-row mb-4" id='secondaryMSISDNList'>
                                                @foreach ($msisdn as  $node)

                                                    <div class="col-3">
                                                        <label class="radio-inline">
                                                        <input class="mr-2" type="radio" id="secondaryMsisdn" name="secondaryMsisdn" value="{{$node}}">{{$node}}</label>
                                                    </div>

                                                @endforeach
                                            </div>
                                        </div>

                                        <div class="form-row">
                                            <div class="col-xs-12 col-md-6">
                                                <div class="form-group">
                                                    <label class="font-weight-bold mb-4" for="blockReason">Select reason for registration of additional SIM number</label>
                                                    <select class="custom-select text-center" id="tcraReason" name="tcraReason">
                                                        <option class="" value=""> --------------Choose reason ------------</option>
                                                        <option value="1000">For additional devices (phones, tablets, CCTV, routers etc)</option>
                                                        <option value="1001">To separate office and private usage</option>
                                                        <option value="1002">To separate business and personal usage</option>
                                                        <option value="1003">For mobile financial services</option>
                                                        <option value="1004">Mobile number porting - with reasons</option>
                                                        <option value="1005">Increase branches/shops or business</option>
                                                    </select>
                                                </div>
                                            </div>
                                        </div>

                                        <div class="modal-footer">
                                            <button id="oneSIMSecondarySubmitTCRA" type="submit" class="btn btn-primary"><span class="fa fa-save"></span> Confirm</button>
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

    <script src="{{ asset('js/one-sim/oneSIMSecondaryTCRA.js') }}"></script>

@endsection
