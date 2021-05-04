@extends('layout.app')

@include('includes.registration.background')

@section('title', 'Register Bulk Msisdn Diplomats')

@section('content')

<section class="section-container">
    <!-- Page content-->
    <div class="content-wrapper" style="overflow-y: hidden">

        <div class="content-heading">
            <div>Diplomat Bulk Registration - Institution Details
            </div>
        </div>

        @include('layout.flash-messages')


        <blockquote id="flash-message" class="p-2 text text-danger h4 ml-3"></blockquote>

        <!-- END chart-->
        <div class="row">
            <div class="col-xl-12">

                <!-- DATATABLE DEMO 2-->
                <div class="card" id="verification-panel" >
                    <div class="card-body ">
                        <div class="container">
                            <form method="post" action="{{ action('KYC\KYCController@bulkDiplomatProcessPage1') }}" class="mb-3" id="registerDiplomatForm" enctype="multipart/form-data">
                                @csrf
                                <div class="row">
                                    <div class="col-2"></div>
                                    <div class="col-8">
                                        <div class="row">
                                            <div class="form-group col-12">
                                                <label class="text-bold">Institution Name </label>
                                                <input class="form-control"  name="institution" >
                                            </div>
                                        </div>

                                        <div class="row">
                                            <div class="form-group col-12">
                                                <label class="text-bold">Region </label>
                                                <select class="custom-select" id="regionID" name="region" onchange="getDistricts(this)">
                                                    <option value="">SELECT REGION</option>
                                                    @foreach ($regions as $item)
                                                        <option value="{{$item['ID']}}">{{$item['Description']}}</option>
                                                    @endforeach
                                                </select>
                                            </div>
                                        </div>

                                        <div class="form-row">
                                            <div class="col-md-12 col-xs-12 mb-3">
                                                <label class="text-bold">District</label>
                                                <select name="district" class="form-control" onchange="getWards(this) "id="district-dropdown">
                                                </select>
                                            </div>
                                        </div>

                                        <div class="form-row">
                                            <div class="col-md-12 col-xs-12 mb-3">
                                                <label class="text-bold">Ward</label>
                                                <select class="form-control" name="ward" onchange="getVillage(this)" id="ward-dropdown"></select>
                                            </div>
                                        </div>

                                        <div class="form-row">
                                            <div class="col-md-12 col-xs-12 mb-3">
                                                <label class="text-bold">Street </label>
                                                <select class="form-control" name="village"  id="village-dropdown"></select>
                                            </div>
                                        </div>

                                        <div class="form-row">
                                            <div class="col-md-12 col-xs-12 mb-3">
                                                <label class="text-bold">Address </label>
                                                <textarea name="adress" id="adress" class="form-control"></textarea>
                                            </div>
                                        </div>

                                        <div class="row">
                                            <div class="form-group col-12">
                                                <label class="text-bold">Post Code </label>
                                                <input class="form-control" type="text"  name="post-code" >
                                            </div>
                                        </div>

                                        <div class="row">
                                            <div class="form-group col-12">
                                                <label class="text-bold" for="exampleInputEmail1">List of MSISDN (.CSV)</label>
                                                <input type="file" class="form-control-file" name="msisdn-file" id="msisdn-file" >
                                            </div>
                                        </div>

                                        <div class="row">
                                            <div class="col-3">
                                                <button id="saveBulkDiplomatBtn1" type="submit" name="saveBulkDiplomatBtn1" class="btn btn-md btn-primary">Next</button>
                                            </div>
                                            <div class="col-3">
                                                <button id="clearFormBtn" name="clearFormBtn" class="btn btn-md btn-default float-right" >Clear Form</button>
                                            </div>
                                        </div>

                                    </div>


                                    <div class="col-2"></div>

                                </div>

                            </form>

                        </div>

                    </div>
                </div>
            </div>
            <!-- DATATABLE-->
        </div>

    </div>

</section>
@endsection

@section('scripts')
    <script src="{{ asset('js/diplomat-bulk.js') }}"></script>
@endsection
