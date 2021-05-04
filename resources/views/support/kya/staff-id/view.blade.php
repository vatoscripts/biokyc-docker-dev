@extends('layout.app')

@section('content')

<!-- Main section-->
<section class="section-container">
    <!-- Page content-->
    <div class="content-wrapper">

        <a href="/support/download/staff-id-pdf"> Download PDF</a>

            <table class="table table-borderless" style="margin: 5px 0; font-size:1.2rem;">
                <tbody>
                    <tr>
                        <tr>
                            <td colspan="2" style="text-align: center"><img class="img-fluid" src="data:image/png;base64, {{ $staff['Photo'] }}" width="240" height="320" alt="Contact"></td>
                        </tr>
                        <tr>
                            <td colspan="2" style="text-align: center"><p>AUTHORISED BY VODACOM TANZANIA PLC <img src="{{ url('img/voda_logo.png') }} " alt="" width="40" height="40" style="background: none"></p> </td>
                        </tr>

                        <tr><td style="padding: 1rem 0 1rem 20rem; font-size:1.5rem; ">  Agent Information</td></tr>
                        {{-- <th scope="row">1</th> --}}
                        <tr style="">
                            <td style="padding: 1rem 0 0.5rem 20rem;">Full Name</td>
                            <td style="padding: 1rem 20rem 0.5rem 0;">{{ $staff['FirstName'] }} {{ $staff['MiddleName'] }} {{ $staff['Surname'] }}</td>
                        </tr>
                        <tr>
                            <td style="padding: 1rem 0 0.5rem 20rem;">Cell Number</td>
                            <td style="padding: 1rem 20rem 0.5rem 0;">{{ $staff['Msisdn'] }}</td>
                        </tr>
                        <tr>
                            <td style="padding: 1rem 0 0.5rem 20rem;">Date of birth</td>
                            <td style="padding: 1rem 20rem 0.5rem 0;">{{ date('jS F Y', strtotime($staff['Dob'])) }}</td>
                        </tr>
                        <tr>
                            <td style="padding: 1rem 0 0.5rem 20rem;">Gender</td>
                            <td style="padding: 1rem 20rem 0.5rem 0;">{{ $staff['Gender'] }}</td>
                        </tr>
                        <tr>
                            <td style="padding: 1rem 0 0.5rem 20rem;">NIN</td>
                            <td style="padding: 1rem 20rem 0.5rem 0;">{{ $staff['NIN'] }}</td>
                        </tr>

                        <tr><td style="padding: 1rem 0 1rem 20rem; font-size:1.5rem; "> Business Information </td></tr>
                        {{-- <th scope="row">1</th> --}}
                        <tr>
                            <td style="padding: 1rem 0 0.5rem 20rem;">Business Name</td>
                            <td style="padding: 1rem 20rem 0.5rem 0;">{{ $staff['BusinessName'] }}</td>
                        </tr>
                        <tr>
                            <td style="padding: 1rem 0 0.5rem 20rem;">Contact Number</td>
                            <td style="padding: 1rem 20rem 0.5rem 0;">{{ $staff['BusinessPhoneNo'] }}</td>
                        </tr>
                        <tr>
                            <td style="padding: 1rem 0 0.5rem 20rem;">TIN</td>
                            <td style="padding: 1rem 20rem 0.5rem 0;">{{ $staff['TIN'] }}</td>
                        </tr>
                        <tr>
                            <td style="padding: 1rem 0 0.5rem 20rem;">Territory</td>
                            <td style="padding: 1rem 20rem 0.5rem 0;">{{ $staff['TerritoryName'] }}</td>
                        </tr>
                        <tr>
                            <td style="padding: 1rem 0 0.5rem 20rem;">Adress</td>
                            <td style="padding: 1rem 20rem 0.5rem 0;">{{ $staff['BusinessLocation']}}</td>
                        </tr>
                    </tr>
                </tbody>
            </table>

    </div>
</section>

@endsection

