@extends('layout.app')

@section('content')


    <!-- Main section-->
    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">
<div class="row">
    <div class="col-lg-4">
        <div class="card card-default">
            <div class="card-body text-center">
                <div class="py-4">
                    <img class="img-fluid rounded-circle img-thumbnail" src="data:image/png;base64, {{$data[0]['Signature']}} ">
                </div>
                <h3 class="m-0 text-bold">{{$data[0]['FirstName']}} {{$data[0]['OtherNames']}} {{$data[0]['Surname']}}</h3>
                <div class="my-3">
                    <p>Registered on <strong>{{ date('Y-m-d h:i:s', strtotime($data[0]['RegDate'])) }}</strong></p>
                </div>
                <div class="text-center">
                    <div class="text text-success"> <em class="fa fa-check-circle fa-3x"></em></div>
                </div>
            </div>
        </div>
        <div class="card card-default d-none d-lg-block">
            <div class="card-header">
                <div class="card-title text-center"><img class="img-fluid" src="data:image/png;base64, {{$data[0]['Photo']}} "></div>
            </div>


        </div>
    </div>
    <div class="col-lg-8">
        <div class="card card-default">
            <div class="card-header d-flex align-items-center align-middle">
               <div align="center" style="width:100%;font-size:18px;" class="alert alert-info"><strong><em class="fa fa-user"> </em> CUSTOMER REGISTRATION DETAILS</strong></div>
            </div>
            <div class="card-body">
                <div class="row py-4 justify-content-center">
                    <div class="col-12 col-sm-10">
                            <div class="form-group row">
                                <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact1">Phone Number</label>
                                <div class="col-xl-10 col-md-9 col-8">
                                    <input class="form-control" id="inputContact2" type="email" value="{{$data[0]['Msisdn']}}" disabled>
                                </div>
                            </div>
                            <div class="form-group row">
                                <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact1">Gender</label>
                                <div class="col-xl-10 col-md-9 col-8">
                                    <input class="form-control" id="inputContact2" type="email" value="{{$data[0]['Sex']}}" disabled>
                                </div>
                            </div>
                            <div class="form-group row">
                                <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact2">Country</label>
                                <div class="col-xl-10 col-md-9 col-8">
                                    <input class="form-control" id="inputContact2" type="email" value="{{$data[0]['Nationality']}}" disabled>
                                </div>
                            </div>
                            <div class="form-group row">
                                <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact3">Reg Type</label>
                                <div class="col-xl-10 col-md-9 col-8">
                                    <input class="form-control" id="inputContact3" type="text" value="{{$data[0]['RegType']}}" disabled>
                                </div>
                            </div>
                            <div class="form-group row">
                                <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact4">Reg Channel</label>
                                <div class="col-xl-10 col-md-9 col-8">
                                    <input class="form-control" id="inputContact4" type="text" value="{{$data[0]['Platform']}}" disabled>
                                </div>
                            </div>
                            <div class="form-group row">
                                <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact3">Agent Name</label>
                                <div class="col-xl-10 col-md-9 col-8">
                                    <input class="form-control" id="inputContact3" type="text" value="{{$data[0]['AgentName']}}" disabled>
                                </div>
                            </div>
                            <div class="form-group row">
                                <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact4">Agent Code</label>
                                <div class="col-xl-10 col-md-9 col-8">
                                    <input class="form-control" id="inputContact4" type="text" value="{{$data[0]['AgentCode']}}" disabled>
                                </div>
                            </div>

                            <div class="form-group row">
                                <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact6">Address</label>
                                <div class="col-xl-10 col-md-9 col-8">
                                    <textarea class="form-control" id="inputContact6" rows="6" disabled>{{$data[0]['ResidentRegion']}},
{{$data[0]['ResidentDistrict']}},
{{$data[0]['ResidentWard']}},
{{$data[0]['ResidentVillage']}},
{{$data[0]['ResidentStreet']}}
                                    </textarea>
                                </div>
                            </div>

                            <div class="form-group row">
                                <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact8">NIN</label>
                                <div class="col-xl-10 col-md-9 col-8">
                                    <input class="form-control" id="inputContact8" type="text" value="{{$data[0]['IDNumber']}}" disabled>
                                </div>
                            </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
        </div></section>

@endsection
