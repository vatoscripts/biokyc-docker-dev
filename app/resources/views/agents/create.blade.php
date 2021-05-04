@extends('layout.register')

@section('title') <small>Register Agent</small> @endsection
@section('content')
    <div class="card">
        <div class="card-body">
            <form method="post" action="{{ url('post-add-agent') }}">
                @csrf
                <input name="NIN" value="{{ old('NIN') }}" class="form-control" type="text" placeholder="Enter NIDA number">
                <div class="m-2">
                    <div id="Div_fingerprint_kya"></div>
                </div>
                <br /><br />
                <div class="modal-footer">
                    <a href="{{ url()->previous() }}" class="btn btn-danger">Cancel</a>
                    <button type="submit" class="btn btn-primary"><span class="fa fa-edit"></span>&nbsp;Onboard Agent</button>
                </div>
            </form>
        </div>
    </div>
@endsection
