@extends('layout.app')

@include('includes.registration.background')

@section('title', 'Register Bulk Msisdn Diplomats')

@section('content')

<section class="section-container">
    <!-- Page content-->
    <div class="content-wrapper" style="overflow-y: hidden">

        <div class="content-heading">
            <div>Diplomat Bulk Registration - SPOC Details
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
                            <form method="post" action="{{ action('KYC\KYCController@bulkDiplomatProcessPage2') }}" class="mb-3" id="registerDiplomatBulkForm2">
                                @csrf
                                <div class="row">

                                    <div class="col-6">
                                        <div class="row">
                                            <div class="form-group col-12">
                                                <label class="text-bold">MSISDN </label>
                                                <input class="form-control" type="text"  name="msisdn" placeholder="Enter MSISDN Like 255754100100">
                                            </div>
                                        </div>

                                        <div class="row">
                                            <div class="form-group col-12">
                                                <label class="text-bold">First Name </label>
                                                <input class="form-control"  name="firstName">
                                            </div>
                                        </div>
                                        <div class="row">
                                            <div class="form-group col-12">
                                                <label class="text-bold">Middle Name </label>
                                                <input class="form-control"  name="middleName">
                                            </div>
                                        </div>
                                        <div class="row">
                                            <div class="form-group col-12">
                                                <label class="text-bold">Last Name </label>
                                                <input class="form-control"  name="lastName" >
                                            </div>
                                        </div>
                                        <div class="row">
                                            <div class="form-group col-12">
                                                <label class="text-bold">Passport Number </label>
                                                <input class="form-control"  name="passport-number" >
                                            </div>
                                        </div>

                                        <div class="row">
                                            <div class="form-group col-12">
                                                <label class="text-bold">EXPIRY DATE </label>
                                                <input class="form-control"  name="expiry-date" placeholder="Enter Expiry Date Like 01-JAN-1900" >
                                            </div>
                                        </div>

                                        <div class="row">
                                            <div class="form-group col-12">
                                                <label class="text-bold">ID Number </label>
                                                <input class="form-control"  name="id-number" >
                                            </div>
                                        </div>

                                    </div>

                                    <div class="col-6">
                                        <div class="row">
                                            <div class="form-group col-12">
                                                <label class="text-bold">DOB </label>
                                                <input class="form-control"  name="dob" placeholder="Enter Date of Birth Like 01-JAN-1900">
                                            </div>
                                        </div>

                                        <div class="row">
                                            <div class="form-group col-12">
                                                <label class="text-bold">Gender </label>
                                                <select class="custom-select" id="gender-select" name="gender">
                                                    <option value="">SELECT GENDER</option>
                                                    <option value="MALE">MALE</option>
                                                    <option value="FEMALE">FEMALE</option>
                                                    <option value="UNSPECIFIED">UNSPECIFIED</option>
                                                </select>
                                            </div>
                                        </div>

                                        <div class="row">
                                            <div class="form-group col-12">
                                                <label class="text-bold">Email Address </label>
                                                <input class="form-control" type="email"  name="email" >
                                            </div>
                                        </div>

                                        <div class="row">
                                            <div class="form-group col-12">
                                                <label class="text-bold">Country </label>
                                                <select class="custom-select" id="country-select" name="country">
                                                    <option value="">SELECT COUNTRY</option>
                                                    @foreach ($country as $item)
                                                        <option value="{{$item['Name']}}">{{$item['Name']}}</option>
                                                    @endforeach
                                                </select>
                                            </div>
                                        </div>

                                        <div class="row">
                                            <div class="form-group col-12">
                                                <label class="text-bold" for="exampleInputEmail1">ID Front Picture or Introduction Letter (.PNG OR .JPEG)</label>
                                                <input type="file" class="form-control-file" name="front-id-file" id="customFile" >
                                            </div>
                                        </div>

                                        <div class="row">
                                            <div class="form-group col-12">
                                                <label class="text-bold" for="exampleInputEmail1">ID Back Picture (.PNG OR .JPEG)</label>
                                                <input type="file" class="form-control-file" name="back-id-file" id="customFile">
                                            </div>
                                        </div>

                                        <div class="row">
                                            <div class="form-group col-12">
                                                <label class="text-bold" for="exampleInputEmail1">Passport Picture (.PNG OR .JPEG)</label>
                                                <input type="file" class="form-control-file" name="passport-file" id="customFile">
                                            </div>
                                        </div>

                                        <div class="row">
                                            <div class="form-group col-12">
                                                <label class="text-bold" for="exampleInputEmail1">Agent ID Picture (.PNG OR .JPEG)</label>
                                                <input type="file" class="form-control-file" name="agentID-file" id="customFile">
                                            </div>
                                        </div>

                                    </div>

                                </div>
                                <div class="row">
                                    <div class="col-3">
                                        <button id="RegisterDiplomatBtn" type="submit" name="RegisterDiplomatBtn" class="btn btn-md btn-primary">Submit Registration</button>
                                    </div>
                                    <div class="col-3">
                                        <button id="clearFormBtn" name="clearFormBtn" class="btn btn-md btn-default float-right" >Clear Form</button>
                                    </div>
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
