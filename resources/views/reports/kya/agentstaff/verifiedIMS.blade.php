@extends('layout.app')

@section('content')

<!-- Main section-->
<section class="section-container">
    <!-- Page content-->
    <div class="content-wrapper">
        <div class="content-heading">
            <div>Staff Verified Report
                <p class="lead mt-2">KYA Reports: View Staff verified.</p>
            </div>
        </div>
        @include('layout.flash-messages')

        @if (isset($staff))
            <!-- DATATABLE DEMO 2-->
            <div class="card" id="agentsbyLocationWrapper">
                <div class="card-body ">
                    @if (count($staff) > 0)
                    <div class="agentsbyLocationReport">
                        <div id="agentsCount" class=""></div>
                        <table class="table table-striped my-4 w-100" id="staffbyAgentTable">
                            <thead>
                                <tr>
                                    <th>Full Name</th>
                                    <th>Business Name</th>
                                    <th>Region</th>
                                    <th class="">District</th>
                                    <th>Date Onboarded</th>
                                </tr>
                            </thead>
                            <tbody>
                                @foreach ($staff as $staffAgent)
                                <tr class="gradeX">
                                    <td>{{$staffAgent['FirstName']}} {{$staffAgent['Surname']}}</td>
                                    <td class="">{{$staffAgent['BusinessName']}}</td>
                                    <td>{{$staffAgent['ImsRegion']}}</td>
                                    <td class="">{{$staffAgent['ImsDistrict']}}</td>
                                    <td class="">{{ date('D, jS F Y G:i:s', strtotime($staffAgent['OnboardedDate'])) }}</td>
                                </tr>
                                @endforeach
                            </tbody>
                        </table>
                    </div>

                    @else
                        <div class="h4 text-danger lead">Oops ! Looks like there are no any Staff(s) for the specified Agent.</div>
                    @endif

                </div>
            </div>
        @endif

    </div>
</section>

@endsection

@section('scripts')

    <script src="{{ asset('js/agentStaffReport.js') }}"></script>



@endsection

