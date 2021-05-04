@extends('layout.app')

@section('content')


<!-- Main section-->
<section class="section-container">
    <!-- Page content-->
    <div class="content-wrapper">
        @include('layout.flash-messages')
        <div class="row">
            <div class="col-lg-4">
                <div class="card b">
                    <div class="card-body text-center">
                        <div class="py-4">
                            <img class="img-fluid rounded-circle" src="data:image/png;base64, {{$agent['Photo']}}" alt="Contact">
                        </div>
                        <h3 class="m-0 text-bold">{{ $agent['FirstName']}} {{ $agent['Surname']}} </h3>

                        <div class="my-3">
                            @if ($agent['ActiveYN']=='Y' )
                            <div class="text text-success mb-2"> <em class="fa fa-check-circle fa-3x"></em></div>
                            <a href="/block-agent/{{ $agent['AgentID'] }}" class="btn btn-block btn-danger"> Deactivate this agent</a>
                            @else
                            <div class="text text-danger mb-2"> <em class="fa fa-minus-circle fa-3x"></em></div>
                            <a href="/unblock-agent/{{ $agent['AgentID'] }}" class="btn btn-block btn-info"> Activate this agent</em></a>
                            @endif
                        </div>

                    </div>
                </div>
                <div class="card b d-none d-lg-block">
                    <div class="card-header">
                        <div class="card-title text-center">Adress/Location</div>
                        <div class="card-body">
                            <div class="form-group">
                                <input type="hidden" id="agent_Id" value="{{$id}}">
                                <label for="">ZONE</label>
                                <select class="form-control" name="" onchange="getregion(this)" id="zone-dropdown"></select>
                            </div>
                            <div class="form-group">
                                <label for="">REGION</label>
                                <select class="form-control" name="" onchange="getterritory(this)" id="region-dropdown"></select>
                            </div>
                            <div class="form-group">
                                <label for="">TERRITORY</label>
                                <select class="form-control" name="" id="territory-dropdown"></select>
                            </div>
                            <input type="button" class="btn btn-danger btn-block" onclick="update_address()" value="UPDATE" />
                        </div>
                    </div>
                </div>

                <div class="card b d-none d-lg-block">
                    <div class="card-header">
                        <div class="card-body">
                            <a class="btn btn-danger btn-block" href="/agent/shops/{{ $agent['AgentID']}}">View Shops</a>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-lg-8">
                <div class="card b">
                    <div class="card-header d-flex align-items-center">
                        <div class="d-flex justify-content-center col">
                            <div class="h3 m-0 text-center">Contact Information</div>
                        </div>

                    </div>
                    <div class="card-body">
                        <div class="row py-4 justify-content-center">
                            <div class="col-12 col-sm-10">
                                <form class="form-horizontal">
                                    <div class="form-group row">
                                        <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact1">Business Name</label>
                                        <div class="col-xl-10 col-md-9 col-8">
                                            <input class="form-control" id="inputContact1" type="text" placeholder="" value="{{ $agent['BusinessName']}} " disabled>
                                        </div>
                                    </div>
                                    <div class="form-group row">
                                        <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact2">TIN</label>
                                        <div class="col-xl-10 col-md-9 col-8">
                                            <input class="form-control" id="inputContact2" type="email" value="{{ $agent['TIN']}}" disabled>
                                        </div>
                                    </div>

                                    <div class="form-group row">
                                        <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact4">Tel</label>
                                        <div class="col-xl-10 col-md-9 col-8">
                                            <input class="form-control" id="inputContact4" type="text" value="{{ $agent['Telephone']}}" disabled>
                                        </div>
                                    </div>

                                    <div class="form-group row">
                                        <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact6">Address</label>
                                        <div class="col-xl-10 col-md-9 col-8">
                                            <textarea class="form-control" id="inputContact6" rows="4" disabled>{{ $agent['Address']}}</textarea>
                                        </div>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="card b">
                    <div class="card-header d-flex align-items-center">
                        <div class="d-flex justify-content-center col">
                            <div class="h3 m-0 text-left">Business Legal Documents</div>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="row py-4 justify-content-center">
                            <div class="col-12 col-sm-10">

                                <div class="row mb-4">
                                    <div class="col-lg-6 col-xs-12">
                                        <span class="font-weight-bold mr-4">TIN certified copy</span>
                                    </div>
                                    <div class="col-lg-6 col-xs-12">
                                        <a href="data:application/pdf;base64, {{$agent['TINDoc']}}" download="{{$agent['BusinessName']}}-TINLicence.pdf"><i class="fa fa-download fa-2x mr-2" aria-hidden="true"></i>Download</a>

                                    </div>
                                </div>
                                <div class="row">
                                    <div class="col-lg-6 col-xs-12">
                                        <span class="font-weight-bold">Licence certified copy</span>
                                    </div>
                                    <div class="col-lg-6 col-xs-12">
                                        <a href="data:application/pdf;base64, {{$agent['LicenceDoc']}}" download="{{$agent['BusinessName']}}-BusinessLicence.pdf">
                                            <i class="fa fa-download fa-2x mr-2" aria-hidden="true"></i>Download
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

            </div>

        </div>
    </div>
</section>

@endsection


@section('scripts')

<script src="{{ asset('js/agents.js') }}"></script>
<script>
    getAgentAddress({
        {
            $agent['ZoneID']
        }
    }, {
        {
            $agent['RegionID']
        }
    }, {
        {
            $agent['TerritoryID']
        }
    });
</script>

@endsection