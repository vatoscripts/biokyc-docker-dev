@extends('layout.app')

@section('content')

<!-- Page content-->
<div class="content-wrapper">
    <div class="row">
        <div class="col-lg-12">
            <div class="card card-default">
                <div class="card-header d-flex align-items-center">
                    <div class="d-flex justify-content-center col">
                        <div class="h4 m-0 text-center">Add New Device</div>
                    </div>
                </div>
                <div class="card-body">
                    <div class="row py-4 justify-content-center">
                        <div class="col-12 col-sm-10">

                            @if ($errors->any())
                            <div class="alert alert-danger">
                                <ul>
                                    @foreach ($errors->all() as $error)
                                    <li>{{ $error }}</li>
                                    @endforeach
                                </ul>
                            </div>
                            @endif

                            <form method="post" action="{{ url('post-add-device') }}" class="form-horizontal">
                                @csrf
                                <div class="form-group row">
                                    <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact1">Device ID</label>
                                    <div class="col-xl-10 col-md-9 col-8">
                                        <input name="DeviceID" value="{{ old('DeviceID') }}" class="form-control" id="inputContact1" type="text" placeholder="" />
                                    </div>
                                </div>
                                <div class="form-group row">
                                    <div class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact3">Distribution model</div>
                                    <div class="col-xl-10 col-md-9 col-8">
                                        <div class="form-check">
                                            <input name="Shared" value="{{ old('Shared') }}" class="form-check-input" type="checkbox" />
                                            <label class="form-check-label" for="gridCheck1">Shared</label>
                                        </div>
                                    </div>
                                </div>
                                <div class="form-group row">
                                    <div class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact3">Status</div>
                                    <div class="col-xl-10 col-md-9 col-8">
                                        <div class="form-check">
                                            <input name="ActiveYN" value="{{ old('ActiveYN') }}" class="form-check-input" type="checkbox" />
                                            <label class="form-check-label" for="gridCheck1">Active</label>
                                        </div>
                                    </div>
                                </div>
                                <div class="form-group row">
                                    <div class="col-xl-10 col-md-9 col-8 offset-2">
                                        <button class="btn btn-primary" type="submit">Save Information</button>
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