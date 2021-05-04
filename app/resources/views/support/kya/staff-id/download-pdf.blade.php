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
            margin-right: auto;
            margin-left: auto;
            width: 100%;
        }

        td.my-center {
        text-align: center;
        vertical-align: top;
        }

        td.my-data {
            font-size:8pt;
            text-align: left;
            vertical-align: top;
        }

        td.my-title {
            font-size:10pt;
            font-weight: bold;
        }
        td.my-title-2 {
            font-size:8pt;
            font-weight: bold;
        }
    </style>
    </head>
    <body>
        <div class="container wrap">
            <table>
                <tbody>
                    <tr><td></td></tr>
                    <tr>
                        <td colspan="2" class="my-center">
                            <img src="data:image/png;base64, {{ $staff['Photo'] }}" width="135" height="150" alt="Contact">
                        </td>
                    </tr>
                    <tr>
                        <td colspan="2" class="my-center">
                            <img src="{{ url('img/Vodacom_Logo.png') }} " alt="" height="30" style="background: none">
                        </td>
                    </tr>
                    <tr><td colspan="2" class="my-title mb-3 mt-3">  Agent Staff Information</td></tr>
                    <tr><td></td><td></td></tr>
                    <tr>
                        <td>
                            <tr><td class="my-data">Full Name</td>
                                <td colspan="2" class="my-data">{{ $staff['FirstName'] }} {{ $staff['MiddleName'] }} {{ $staff['Surname'] }}</td>
                            </tr>
                            <tr><td class="my-data">Cell Number</td>
                                <td colspan="2" class="my-data">{{ $staff['Msisdn'] }}</td>
                            </tr>
                            <tr><td class="my-data">Date of birth</td>
                                <td colspan="2" class="my-data">{{ date('jS F Y', strtotime($staff['Dob'])) }}</td>
                            </tr>
                            <tr><td class="my-data"> Gender</td>
                                <td colspan="2" class="my-data">{{ $staff['Gender'] }}</td>
                            </tr>
                            <tr><td class="my-data">NIDA ID</td>
                                <td colspan="2" class="my-data"> {{ $staff['NIN'] }}</td>
                            </tr>
                        </td>
                    </tr>

                    <tr><td></td><td></td></tr>
                    <tr><td colspan="2" class="my-title mb-3 mt-3">Agent Business Information</td></tr>
                    <tr><td></td><td></td></tr>
                    <tr>
                        <td>
                            <tr><td class="my-data">Business Name</td>
                                <td colspan="2" class="my-data">{{ $staff['BusinessName'] }}</td>
                            </tr>
                            <tr><td class="my-data">Contact Number</td>
                                <td colspan="2" class="my-data">{{ $staff['BusinessPhoneNo'] }}</td>
                            </tr>
                            <tr><td class="my-data">TIN</td>
                                <td colspan="2" class="my-data">{{ $staff['TIN'] }}</td>
                            </tr>
                            <tr><td class="my-data">Territory</td>
                                <td colspan="2" class="my-data">{{ $staff['TerritoryName'] }}</td>
                            </tr>
                            <tr><td class="my-data">Adress</td>
                                <td colspan="2" class="my-data">{{ $staff['BusinessLocation']}}</td>
                            </tr>
                        </td>
                    </tr>
                    <tr><td></td></tr>

                    <tr><td colspan="2" class="my-title-2 mb-3 mt-4">AUTHORISED BY : VODACOM TANZANIA PLC </td></tr>
                </tbody>
            </table>

      </div>
  </body>
</html>
