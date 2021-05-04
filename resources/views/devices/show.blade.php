@extends('layout.app')

@section('content')

<!-- Page content-->
<div class="content-wrapper">
    <div class="row">
        <div class="col-lg-12">
            <div class="card card-default">
                <div class="card-header d-flex align-items-center">
                    <div class="d-flex justify-content-center col">
                        <div class="h4 m-0 text-center">Device Information</div>
                    </div>
                </div>
                <div class="card-body">
                    <div class="row py-4 justify-content-center">
                        <div class="col-12 col-sm-10">
                            <form class="form-horizontal">
                                <div class="form-group row">
                                    <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact1">Device ID</label>
                                    <div class="col-xl-10 col-md-9 col-8">
                                        <input class="form-control" id="inputContact1" disabled type="text" placeholder="" value="{{ $item['DeviceID'] }}">
                                    </div>
                                </div>
                                <div class="form-group row">
                                    <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact2">Distribution model</label>
                                    <div class="col-xl-10 col-md-9 col-8">
                                        <input class="form-control" id="inputContact2" disabled type="text" value="{{ $item['Shared'] ? 'Shared' : 'Not shared' }}">
                                    </div>
                                </div>
                                <div class="form-group row">
                                    <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact3">Status</label>
                                    <div class="col-xl-10 col-md-9 col-8">
                                        <input class="form-control" id="inputContact3" disabled type="text" value="{{ $item['ActiveYN'] == 'Y' ? 'Active' : 'Inactive' }}">
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

@endsection