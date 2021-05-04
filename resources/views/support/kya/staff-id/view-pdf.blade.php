<!DOCTYPE html>
<html>
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
    <script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script>
    <style>
        .wrap {
            font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        table {
            font-size:1.7rem;
            width: 80%;
            margin-right: auto;
            margin-left: auto;
        }

        td.my-center {
        text-align: center;
        vertical-align: top;
        }

        td.my-data {
        text-align: left;
        vertical-align: top;
        }
    </style>
    </head>
    <body>
        <a href="/support/download/staff-id-pdf"> Download PDF</a>
        <div class="container wrap">
            <table>
                <tbody>
                    <tr>
                        <td colspan="2" class="my-center">
                            <img src="data:image/png;base64, {{ $staff['Photo'] }}" width="360" height="480" alt="Contact">
                            <p class="title">AUTHORISED BY VODACOM TANZANIA PLC <img src="{{ url('img/Vodacom_Logo.png') }} " alt="" height="100" style="background: none"></p>
                        </td>
                    </tr>

                    <tr>
                        <td class="my-data">
                        <tr><td><h3 class="mt-3 mb-3 text-bold">  Agent Staff Information</h3></td></tr>
                        <tr><td>Full Name</td>
                            <td colspan="2">{{ $staff['FirstName'] }} {{ $staff['MiddleName'] }} {{ $staff['Surname'] }}</td>
                        </tr>
                        <tr><td>Cell Number</td>
                            <td colspan="2">{{ $staff['Msisdn'] }}</td>
                        </tr>
                        <tr><td>Date of birth</td>
                            <td colspan="2">{{ date('jS F Y', strtotime($staff['Dob'])) }}</td>
                        </tr>
                        <tr><td> Gender</td>
                            <td colspan="2">{{ $staff['Gender'] }}</td>
                        </tr>
                        <tr><td>NIN</td>
                            <td colspan="2"> {{ $staff['NIN'] }}</td>
                        </tr>

                        <tr><td><h3 class="mb-3 mt-3">Agent Business Information</h3></td></tr>
                        <tr><td>Business Name</td>
                            <td colspan="2">{{ $staff['BusinessName'] }}</td>
                        </tr>
                        <tr><td>Contact Number</td>
                            <td colspan="2">{{ $staff['BusinessPhoneNo'] }}</td>
                        </tr>
                        <tr><td>TIN</td>
                            <td colspan="2">{{ $staff['TIN'] }}</td>
                        </tr>
                        <tr><td>Territory</td>
                            <td colspan="2">{{ $staff['TerritoryName'] }}</td>
                        </tr>
                        <tr><td>Adress</td>
                            <td colspan="2">{{ $staff['BusinessLocation']}}</td>
                        </tr>
                    </td>
                    </tr>

                </tbody>
            </table>
      </div>
  </body>
</html>
