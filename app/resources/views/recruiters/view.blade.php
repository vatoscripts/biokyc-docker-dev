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
                                <img class="img-fluid rounded-circle" src="data:image/png;base64, {{$agent['photo']}}" alt="Contact">
                            </div>
                            <h3 class="m-0 text-bold">{{ $agent['FirstName']}} {{ $agent['Surname']}} </h3>

                            <div class="my-3">
                                @if ($agent['ActiveYN']=='Y' )
                                    <div class="text text-success mb-2"> <em class="fa fa-check-circle fa-3x"></em></div>
                                    <a href="/block-staff-recruiter/{{ $agent['ProfileID'] }}" class="btn btn-block btn-danger"> Deactivate this Recruiter</a>
                                @else
                                    <div class="text text-danger mb-2"> <em class="fa fa-minus-circle fa-3x"></em></div>
                                    <a href="/unblock-staff-recruiter/{{ $agent['ProfileID'] }}" class="btn btn-block btn-info"> Activate this Recruiter</em></a>
                                @endif
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
                                            <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact1">Business  Name</label>
                                            <div class="col-xl-10 col-md-9 col-8">
                                                <input class="form-control" id="inputContact1" type="text" placeholder="" value="{{ $agent['BusinessName']}} " disabled>
                                            </div>
                                        </div>
                                        <div class="form-group row">
                                            <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact1">Phone Number</label>
                                            <div class="col-xl-10 col-md-9 col-8">
                                                <input class="form-control" id="inputContact1" type="text" placeholder="" value="{{ $agent['phone']}} " disabled>
                                            </div>
                                        </div>
                                        <div class="form-group row">
                                            <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact2">Agent </label>
                                            <div class="col-xl-10 col-md-9 col-8">
                                                <a href="/agent/{{$agent['AgentID']}}" class="btn btn-link">Click to View Agent</a>
                                            </div>
                                        </div>

                                    </form>
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

@endsection
