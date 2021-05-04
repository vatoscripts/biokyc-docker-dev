@extends('layout.app')

@include('includes.registration.background')



@section('content')

<section class="section-container">
    <!-- Page content-->
    <div class="content-wrapper">

        <div class="content-heading">
            <div>Registered Diplomats
            </div>
        </div>

        @include('layout.flash-messages')

        <blockquote id="flash-message" class="p-2 text text-danger h4 ml-3"></blockquote>

        <!-- END chart-->
        <div class="row">
            <div class="col-xl-12">
                @if ($diplomat)
                    <div class="card">
                        <div class="card-body">
                            <table class="table table-striped table-hover w-100" id="datatable2">
                                <thead>
                                    <tr>
                                        <th data-priority="1">Phone Number</th>
                                        <th>Full Name</th>
                                        <th>Institution</th>
                                        <th>Country</th>
                                        <th>Date Registered</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    @foreach ($diplomat as $item)
                                        <tr>
                                            <td>{{ $item['MSISDN'] }}</td>
                                            <td>{{ $item['FullName'] }}</td>
                                            <td>{{ $item['Institution'] }}</td>
                                            <td>{{ $item['Country'] }}</td>
                                            <td>{{date('Y-m-d h:i:s', strtotime( $item['RegDate']))}}</td>
                                        </tr>
                                    @endforeach
                                </tbody>
                                </table>
                        </div>
                    </div>
                @else
                <div class="card">
                    <div class="card-body">
                    <h3 class="text text-danger lead"><strong>Looks like there are no any Registrations !</strong></h3>
                    </div>
                </div>
                @endif
            </div>
        </div>
    </div>

</section>
@endsection

@section('scripts')
    <script src="{{ asset('js/check-registration.js') }}"></script>
@endsection
