<?php

namespace App\Http\Controllers\KYC;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Session;
use App\Http\Controllers\GuzzleController as GuzzleController;
use App\Http\Requests\OneSIMKYCRequest;
use Illuminate\Support\Facades\Log;
use Route;

class RegistrationController extends GuzzleController
{
    public function __construct()
    {
        parent::__constructor();
        $this->middleware(['role:ROLE_REGISTRAL,ROLE_SPECIAL_REGISTRAL,ROLE_MAKER']);
        $this->middleware(['role:ROLE_SPECIAL_REGISTRAL'])->only(['viewMinorRegistrationCheck', 'viewMinorRegistrationPrimary', 'diplomatStartPage', 'diplomatRegisterPrimaryPage', 'diplomatRegisterSecondaryPage', 'viewBulkRegistrationStart', 'viewBulkRegistrationPrimarySPOC', 'viewBulkRegistrationPrimarySave', 'bulkRegistrationSecondarySPOCPage', 'bulkRegistrationSecondaryCompanyPage']);
    }

    public function viewOneSIMStart()
    {
        session()->forget(['msisdnSecondaryNIDA','NINSecondaryNIDA','msisdnPrimaryNIDA','NINPrimaryNIDA','previous-route']);

        return view('register.one-sim.nida.start');

    }

    public function viewOneSIMRegisterPrimary()
    {
        if(Session::has('previous-route') && Session::get('previous-route') == 'api.nida.check')
        {
            return view('register.one-sim.nida.primary');
        }
        else {
            return redirect()->route('one-sim.register');
        }
    }

    public function viewOneSIMRegisterSecondary()
    {
        if(Session::has('previous-route') && Session::get('previous-route') == 'api.nida.check')
        {
            return view('register.one-sim.nida.secondary');
        }
        else {
            return redirect()->route('one-sim.register');
        }
    }

    public function diplomatStartPage()
    {
        session::forget(['previous-route','msisdnPrimaryDiplomat', 'passportPrimaryDiplomat', 'msisdnSecondaryDiplomat', 'passportSecondaryDiplomat']);
        return view('register.one-sim.diplomat.start');
    }

    public function diplomatRegisterPrimaryPage()
    {
        if(Session::has('previous-route') && Session::get('previous-route') == 'api.diplomat.check')
        {
            //session()->forget('previous-route');
            return view('register.one-sim.diplomat.primary');
        }
        else {
            return redirect()->route('one-sim.register.diplomat');
        }
    }

    public function diplomatRegisterSecondaryPage()
    {
        if(Session::has('previous-route') && Session::get('previous-route') == 'api.diplomat.check')
        {
            //session()->forget('previous-route');
            return view('register.one-sim.diplomat.secondary');
        }
        else {
            return redirect()->route('one-sim.register.diplomat');
        }
    }

    public function viewVisitorStart()
    {
        session::forget(['msisdnPrimaryVisitor', 'passportPrimaryVisitor', 'msisdnSecondaryVisitor', 'passportSecondaryVisitor',]);
        return view('register.one-sim.visitor.start');
    }

    public function viewVisitorRegisterPrimary()
    {
        if(Session::has('previous-route') && Session::get('previous-route') == 'api.visitor.check')
        {
            //session()->forget('previous-route');
            return view('register.one-sim.visitor.primary')->with('country', $this->ImmigrationCountryList());
        }
        else {
            return redirect()->route('one-sim.register.visitor');
        }
    }

    public function viewVisitorRegisterSecondary()
    {
        if(Session::has('previous-route') && Session::get('previous-route') == 'api.visitor.check')
        {
            //session()->forget('previous-route');
            return view('register.one-sim.visitor.secondary')->with('country', $this->ImmigrationCountryList());
        }
        else {
            return redirect()->route('one-sim.register.visitor');
        }
    }

    public function viewBulkRegistrationStart()
    {
        session::forget(['NIDAdata', 'spoc', 'companyName']);

        return view('register.one-sim.bulk.start');
    }

    public function viewBulkRegistrationPrimarySPOC()
    {
        return view('register.one-sim.bulk.primary.spoc');
    }

    public function viewBulkRegistrationPrimarySave()
    {
        return view('register.one-sim.bulk.primary.company');
    }

    public function viewMinorRegistrationCheck()
    {
        session::forget(['msisdnMinor', 'previous-route']);
        return view('register.one-sim.minor.start');
    }

    public function viewMinorRegistrationPrimary()
    {
        if(Session::has('previous-route') && Session::get('previous-route') == 'api.register.minor.check')
        {
            //session()->forget('previous-route');
            return view('register.one-sim.minor.primary');
        }
        else {
            return redirect()->route('one-sim.minor');
        }
    }

    public function setPrimaryStartPage()
    {
        session::forget(['msisdnPrimary', 'previous-route', 'IDPrimary']);
        return view('register.one-sim.primary.start');
    }

    public function setPrimaryPage()
    {
        if(Session::has('previous-route') && Session::get('previous-route') == 'api.primary.check')
        {
            return view('register.one-sim.primary.set');
        }
        else {
            return redirect()->route('one-sim.primary.start');
        }
    }

    public function setSecondaryStartPage()
    {
        session::forget(['msisdnSecondary', 'previous-route', 'IDSecondary']);
        return view('register.one-sim.secondary.start');
    }

    public function setSecondaryPage()
    {
        if(Session::has('previous-route') && Session::get('previous-route') == 'api.secondary.check') {
            return view('register.one-sim.secondary.set');
        }
        else {
            return redirect()->route('one-sim.secondary.start');
        }
    }

    public function bulkRegistrationSecondarySPOCPage()
    {
        return view('register.one-sim.bulk.secondary.spoc');
    }

    public function bulkRegistrationSecondaryCompanyPage()
    {
        return view('register.one-sim.bulk.secondary.company');
    }

    public function bulkDeclarationStartPage()
    {
        return view('register.one-sim.bulk.declaration.start');
    }

    public function bulkDeclarationSecondPage()
    {
        return view('register.one-sim.bulk.declaration.second');
    }

    public function deRegNidaPage()
    {
        session::forget(['deregMsisdnList', 'previous-route', 'DeregPrimaryMsisdn']);
        return view('register.de-reg.de-register-nida');
    }

    public function deRegMsisdnPage()
    {
        if(Session::has('previous-route') && Session::get('previous-route') == 'api.dereg.nida') {
            return view('register.de-reg.de-register-msisdn');
        }
        else {
            return view('register.de-reg.de-register-nida');
        }
    }

    public function deRegCodePage()
    {
        if(Session::has('previous-route') && Session::get('previous-route') == 'api.dereg.msisdn') {
            return view('register.de-reg.de-register-code');
        }
        else {
            return view('register.de-reg.de-register-nida');
        }
    }


    private function getCountryList() {
        return  array ( 0 => array ( 'Code' => 'AF', 'Name' => 'Afghanistan', ), 1 => array ( 'Code' => 'AX', 'Name' => 'Åland Islands', ), 2 => array ( 'Code' => 'AL', 'Name' => 'Albania', ), 3 => array ( 'Code' => 'DZ', 'Name' => 'Algeria', ), 4 => array ( 'Code' => 'AS', 'Name' => 'American Samoa', ), 5 => array ( 'Code' => 'AD', 'Name' => 'Andorra', ), 6 => array ( 'Code' => 'AO', 'Name' => 'Angola', ), 7 => array ( 'Code' => 'AI', 'Name' => 'Anguilla', ), 8 => array ( 'Code' => 'AQ', 'Name' => 'Antarctica', ), 9 => array ( 'Code' => 'AG', 'Name' => 'Antigua and Barbuda', ), 10 => array ( 'Code' => 'AR', 'Name' => 'Argentina', ), 11 => array ( 'Code' => 'AM', 'Name' => 'Armenia', ), 12 => array ( 'Code' => 'AW', 'Name' => 'Aruba', ), 13 => array ( 'Code' => 'AU', 'Name' => 'Australia', ), 14 => array ( 'Code' => 'AT', 'Name' => 'Austria', ), 15 => array ( 'Code' => 'AZ', 'Name' => 'Azerbaijan', ), 16 => array ( 'Code' => 'BS', 'Name' => 'Bahamas', ), 17 => array ( 'Code' => 'BH', 'Name' => 'Bahrain', ), 18 => array ( 'Code' => 'BD', 'Name' => 'Bangladesh', ), 19 => array ( 'Code' => 'BB', 'Name' => 'Barbados', ), 20 => array ( 'Code' => 'BY', 'Name' => 'Belarus', ), 21 => array ( 'Code' => 'BE', 'Name' => 'Belgium', ), 22 => array ( 'Code' => 'BZ', 'Name' => 'Belize', ), 23 => array ( 'Code' => 'BJ', 'Name' => 'Benin', ), 24 => array ( 'Code' => 'BM', 'Name' => 'Bermuda', ), 25 => array ( 'Code' => 'BT', 'Name' => 'Bhutan', ), 26 => array ( 'Code' => 'BO', 'Name' => 'Bolivia, Plurinational State of', ), 27 => array ( 'Code' => 'BQ', 'Name' => 'Bonaire, Sint Eustatius and Saba', ), 28 => array ( 'Code' => 'BA', 'Name' => 'Bosnia and Herzegovina', ), 29 => array ( 'Code' => 'BW', 'Name' => 'Botswana', ), 30 => array ( 'Code' => 'BV', 'Name' => 'Bouvet Island', ), 31 => array ( 'Code' => 'BR', 'Name' => 'Brazil', ), 32 => array ( 'Code' => 'IO', 'Name' => 'British Indian Ocean Territory', ), 33 => array ( 'Code' => 'BN', 'Name' => 'Brunei Darussalam', ), 34 => array ( 'Code' => 'BG', 'Name' => 'Bulgaria', ), 35 => array ( 'Code' => 'BF', 'Name' => 'Burkina Faso', ), 36 => array ( 'Code' => 'BI', 'Name' => 'Burundi', ), 37 => array ( 'Code' => 'KH', 'Name' => 'Cambodia', ), 38 => array ( 'Code' => 'CM', 'Name' => 'Cameroon', ), 39 => array ( 'Code' => 'CA', 'Name' => 'Canada', ), 40 => array ( 'Code' => 'CV', 'Name' => 'Cape Verde', ), 41 => array ( 'Code' => 'KY', 'Name' => 'Cayman Islands', ), 42 => array ( 'Code' => 'CF', 'Name' => 'Central African Republic', ), 43 => array ( 'Code' => 'TD', 'Name' => 'Chad', ), 44 => array ( 'Code' => 'CL', 'Name' => 'Chile', ), 45 => array ( 'Code' => 'CN', 'Name' => 'China', ), 46 => array ( 'Code' => 'CX', 'Name' => 'Christmas Island', ), 47 => array ( 'Code' => 'CC', 'Name' => 'Cocos (Keeling) Islands', ), 48 => array ( 'Code' => 'CO', 'Name' => 'Colombia', ), 49 => array ( 'Code' => 'KM', 'Name' => 'Comoros', ), 50 => array ( 'Code' => 'CG', 'Name' => 'Congo', ), 51 => array ( 'Code' => 'CD', 'Name' => 'Congo, the Democratic Republic of the', ), 52 => array ( 'Code' => 'CK', 'Name' => 'Cook Islands', ), 53 => array ( 'Code' => 'CR', 'Name' => 'Costa Rica', ), 54 => array ( 'Code' => 'CI', 'Name' => 'Côte d\'Ivoire', ), 55 => array ( 'Code' => 'HR', 'Name' => 'Croatia', ), 56 => array ( 'Code' => 'CU', 'Name' => 'Cuba', ), 57 => array ( 'Code' => 'CW', 'Name' => 'Curaçao', ), 58 => array ( 'Code' => 'CY', 'Name' => 'Cyprus', ), 59 => array ( 'Code' => 'CZ', 'Name' => 'Czech Republic', ), 60 => array ( 'Code' => 'DK', 'Name' => 'Denmark', ), 61 => array ( 'Code' => 'DJ', 'Name' => 'Djibouti', ), 62 => array ( 'Code' => 'DM', 'Name' => 'Dominica', ), 63 => array ( 'Code' => 'DO', 'Name' => 'Dominican Republic', ), 64 => array ( 'Code' => 'EC', 'Name' => 'Ecuador', ), 65 => array ( 'Code' => 'EG', 'Name' => 'Egypt', ), 66 => array ( 'Code' => 'SV', 'Name' => 'El Salvador', ), 67 => array ( 'Code' => 'GQ', 'Name' => 'Equatorial Guinea', ), 68 => array ( 'Code' => 'ER', 'Name' => 'Eritrea', ), 69 => array ( 'Code' => 'EE', 'Name' => 'Estonia', ), 70 => array ( 'Code' => 'ET', 'Name' => 'Ethiopia', ), 71 => array ( 'Code' => 'FK', 'Name' => 'Falkland Islands (Malvinas)', ), 72 => array ( 'Code' => 'FO', 'Name' => 'Faroe Islands', ), 73 => array ( 'Code' => 'FJ', 'Name' => 'Fiji', ), 74 => array ( 'Code' => 'FI', 'Name' => 'Finland', ), 75 => array ( 'Code' => 'FR', 'Name' => 'France', ), 76 => array ( 'Code' => 'GF', 'Name' => 'French Guiana', ), 77 => array ( 'Code' => 'PF', 'Name' => 'French Polynesia', ), 78 => array ( 'Code' => 'TF', 'Name' => 'French Southern Territories', ), 79 => array ( 'Code' => 'GA', 'Name' => 'Gabon', ), 80 => array ( 'Code' => 'GM', 'Name' => 'Gambia', ), 81 => array ( 'Code' => 'GE', 'Name' => 'Georgia', ), 82 => array ( 'Code' => 'DE', 'Name' => 'Germany', ), 83 => array ( 'Code' => 'GH', 'Name' => 'Ghana', ), 84 => array ( 'Code' => 'GI', 'Name' => 'Gibraltar', ), 85 => array ( 'Code' => 'GR', 'Name' => 'Greece', ), 86 => array ( 'Code' => 'GL', 'Name' => 'Greenland', ), 87 => array ( 'Code' => 'GD', 'Name' => 'Grenada', ), 88 => array ( 'Code' => 'GP', 'Name' => 'Guadeloupe', ), 89 => array ( 'Code' => 'GU', 'Name' => 'Guam', ), 90 => array ( 'Code' => 'GT', 'Name' => 'Guatemala', ), 91 => array ( 'Code' => 'GG', 'Name' => 'Guernsey', ), 92 => array ( 'Code' => 'GN', 'Name' => 'Guinea', ), 93 => array ( 'Code' => 'GW', 'Name' => 'Guinea-Bissau', ), 94 => array ( 'Code' => 'GY', 'Name' => 'Guyana', ), 95 => array ( 'Code' => 'HT', 'Name' => 'Haiti', ), 96 => array ( 'Code' => 'HM', 'Name' => 'Heard Island and McDonald Islands', ), 97 => array ( 'Code' => 'VA', 'Name' => 'Holy See (Vatican City State)', ), 98 => array ( 'Code' => 'HN', 'Name' => 'Honduras', ), 99 => array ( 'Code' => 'HK', 'Name' => 'Hong Kong', ), 100 => array ( 'Code' => 'HU', 'Name' => 'Hungary', ), 101 => array ( 'Code' => 'IS', 'Name' => 'Iceland', ), 102 => array ( 'Code' => 'IN', 'Name' => 'India', ), 103 => array ( 'Code' => 'ID', 'Name' => 'Indonesia', ), 104 => array ( 'Code' => 'IR', 'Name' => 'Iran, Islamic Republic of', ), 105 => array ( 'Code' => 'IQ', 'Name' => 'Iraq', ), 106 => array ( 'Code' => 'IE', 'Name' => 'Ireland', ), 107 => array ( 'Code' => 'IM', 'Name' => 'Isle of Man', ), 108 => array ( 'Code' => 'IL', 'Name' => 'Israel', ), 109 => array ( 'Code' => 'IT', 'Name' => 'Italy', ), 110 => array ( 'Code' => 'JM', 'Name' => 'Jamaica', ), 111 => array ( 'Code' => 'JP', 'Name' => 'Japan', ), 112 => array ( 'Code' => 'JE', 'Name' => 'Jersey', ), 113 => array ( 'Code' => 'JO', 'Name' => 'Jordan', ), 114 => array ( 'Code' => 'KZ', 'Name' => 'Kazakhstan', ), 115 => array ( 'Code' => 'KE', 'Name' => 'Kenya', ), 116 => array ( 'Code' => 'KI', 'Name' => 'Kiribati', ), 117 => array ( 'Code' => 'KP', 'Name' => 'Korea, Democratic People\'s Republic of', ), 118 => array ( 'Code' => 'KR', 'Name' => 'Korea, Republic of', ), 119 => array ( 'Code' => 'KW', 'Name' => 'Kuwait', ), 120 => array ( 'Code' => 'KG', 'Name' => 'Kyrgyzstan', ), 121 => array ( 'Code' => 'LA', 'Name' => 'Lao People\'s Democratic Republic', ), 122 => array ( 'Code' => 'LV', 'Name' => 'Latvia', ), 123 => array ( 'Code' => 'LB', 'Name' => 'Lebanon', ), 124 => array ( 'Code' => 'LS', 'Name' => 'Lesotho', ), 125 => array ( 'Code' => 'LR', 'Name' => 'Liberia', ), 126 => array ( 'Code' => 'LY', 'Name' => 'Libya', ), 127 => array ( 'Code' => 'LI', 'Name' => 'Liechtenstein', ), 128 => array ( 'Code' => 'LT', 'Name' => 'Lithuania', ), 129 => array ( 'Code' => 'LU', 'Name' => 'Luxembourg', ), 130 => array ( 'Code' => 'MO', 'Name' => 'Macao', ), 131 => array ( 'Code' => 'MK', 'Name' => 'Macedonia, the Former Yugoslav Republic of', ), 132 => array ( 'Code' => 'MG', 'Name' => 'Madagascar', ), 133 => array ( 'Code' => 'MW', 'Name' => 'Malawi', ), 134 => array ( 'Code' => 'MY', 'Name' => 'Malaysia', ), 135 => array ( 'Code' => 'MV', 'Name' => 'Maldives', ), 136 => array ( 'Code' => 'ML', 'Name' => 'Mali', ), 137 => array ( 'Code' => 'MT', 'Name' => 'Malta', ), 138 => array ( 'Code' => 'MH', 'Name' => 'Marshall Islands', ), 139 => array ( 'Code' => 'MQ', 'Name' => 'Martinique', ), 140 => array ( 'Code' => 'MR', 'Name' => 'Mauritania', ), 141 => array ( 'Code' => 'MU', 'Name' => 'Mauritius', ), 142 => array ( 'Code' => 'YT', 'Name' => 'Mayotte', ), 143 => array ( 'Code' => 'MX', 'Name' => 'Mexico', ), 144 => array ( 'Code' => 'FM', 'Name' => 'Micronesia, Federated States of', ), 145 => array ( 'Code' => 'MD', 'Name' => 'Moldova, Republic of', ), 146 => array ( 'Code' => 'MC', 'Name' => 'Monaco', ), 147 => array ( 'Code' => 'MN', 'Name' => 'Mongolia', ), 148 => array ( 'Code' => 'ME', 'Name' => 'Montenegro', ), 149 => array ( 'Code' => 'MS', 'Name' => 'Montserrat', ), 150 => array ( 'Code' => 'MA', 'Name' => 'Morocco', ), 151 => array ( 'Code' => 'MZ', 'Name' => 'Mozambique', ), 152 => array ( 'Code' => 'MM', 'Name' => 'Myanmar', ), 153 => array ( 'Code' => 'NA', 'Name' => 'Namibia', ), 154 => array ( 'Code' => 'NR', 'Name' => 'Nauru', ), 155 => array ( 'Code' => 'NP', 'Name' => 'Nepal', ), 156 => array ( 'Code' => 'NL', 'Name' => 'Netherlands', ), 157 => array ( 'Code' => 'NC', 'Name' => 'New Caledonia', ), 158 => array ( 'Code' => 'NZ', 'Name' => 'New Zealand', ), 159 => array ( 'Code' => 'NI', 'Name' => 'Nicaragua', ), 160 => array ( 'Code' => 'NE', 'Name' => 'Niger', ), 161 => array ( 'Code' => 'NG', 'Name' => 'Nigeria', ), 162 => array ( 'Code' => 'NU', 'Name' => 'Niue', ), 163 => array ( 'Code' => 'NF', 'Name' => 'Norfolk Island', ), 164 => array ( 'Code' => 'MP', 'Name' => 'Northern Mariana Islands', ), 165 => array ( 'Code' => 'NO', 'Name' => 'Norway', ), 166 => array ( 'Code' => 'OM', 'Name' => 'Oman', ), 167 => array ( 'Code' => 'PK', 'Name' => 'Pakistan', ), 168 => array ( 'Code' => 'PW', 'Name' => 'Palau', ), 169 => array ( 'Code' => 'PS', 'Name' => 'Palestine, State of', ), 170 => array ( 'Code' => 'PA', 'Name' => 'Panama', ), 171 => array ( 'Code' => 'PG', 'Name' => 'Papua New Guinea', ), 172 => array ( 'Code' => 'PY', 'Name' => 'Paraguay', ), 173 => array ( 'Code' => 'PE', 'Name' => 'Peru', ), 174 => array ( 'Code' => 'PH', 'Name' => 'Philippines', ), 175 => array ( 'Code' => 'PN', 'Name' => 'Pitcairn', ), 176 => array ( 'Code' => 'PL', 'Name' => 'Poland', ), 177 => array ( 'Code' => 'PT', 'Name' => 'Portugal', ), 178 => array ( 'Code' => 'PR', 'Name' => 'Puerto Rico', ), 179 => array ( 'Code' => 'QA', 'Name' => 'Qatar', ), 180 => array ( 'Code' => 'RE', 'Name' => 'Réunion', ), 181 => array ( 'Code' => 'RO', 'Name' => 'Romania', ), 182 => array ( 'Code' => 'RU', 'Name' => 'Russian Federation', ), 183 => array ( 'Code' => 'RW', 'Name' => 'Rwanda', ), 184 => array ( 'Code' => 'BL', 'Name' => 'Saint Barthélemy', ), 185 => array ( 'Code' => 'SH', 'Name' => 'Saint Helena, Ascension and Tristan da Cunha', ), 186 => array ( 'Code' => 'KN', 'Name' => 'Saint Kitts and Nevis', ), 187 => array ( 'Code' => 'LC', 'Name' => 'Saint Lucia', ), 188 => array ( 'Code' => 'MF', 'Name' => 'Saint Martin (French part)', ), 189 => array ( 'Code' => 'PM', 'Name' => 'Saint Pierre and Miquelon', ), 190 => array ( 'Code' => 'VC', 'Name' => 'Saint Vincent and the Grenadines', ), 191 => array ( 'Code' => 'WS', 'Name' => 'Samoa', ), 192 => array ( 'Code' => 'SM', 'Name' => 'San Marino', ), 193 => array ( 'Code' => 'ST', 'Name' => 'Sao Tome and Principe', ), 194 => array ( 'Code' => 'SA', 'Name' => 'Saudi Arabia', ), 195 => array ( 'Code' => 'SN', 'Name' => 'Senegal', ), 196 => array ( 'Code' => 'RS', 'Name' => 'Serbia', ), 197 => array ( 'Code' => 'SC', 'Name' => 'Seychelles', ), 198 => array ( 'Code' => 'SL', 'Name' => 'Sierra Leone', ), 199 => array ( 'Code' => 'SG', 'Name' => 'Singapore', ), 200 => array ( 'Code' => 'SX', 'Name' => 'Sint Maarten (Dutch part)', ), 201 => array ( 'Code' => 'SK', 'Name' => 'Slovakia', ), 202 => array ( 'Code' => 'SI', 'Name' => 'Slovenia', ), 203 => array ( 'Code' => 'SB', 'Name' => 'Solomon Islands', ), 204 => array ( 'Code' => 'SO', 'Name' => 'Somalia', ), 205 => array ( 'Code' => 'ZA', 'Name' => 'South Africa', ), 206 => array ( 'Code' => 'GS', 'Name' => 'South Georgia and the South Sandwich Islands', ), 207 => array ( 'Code' => 'SS', 'Name' => 'South Sudan', ), 208 => array ( 'Code' => 'ES', 'Name' => 'Spain', ), 209 => array ( 'Code' => 'LK', 'Name' => 'Sri Lanka', ), 210 => array ( 'Code' => 'SD', 'Name' => 'Sudan', ), 211 => array ( 'Code' => 'SR', 'Name' => 'Suriname', ), 212 => array ( 'Code' => 'SJ', 'Name' => 'Svalbard and Jan Mayen', ), 213 => array ( 'Code' => 'SZ', 'Name' => 'Swaziland', ), 214 => array ( 'Code' => 'SE', 'Name' => 'Sweden', ), 215 => array ( 'Code' => 'CH', 'Name' => 'Switzerland', ), 216 => array ( 'Code' => 'SY', 'Name' => 'Syrian Arab Republic', ), 217 => array ( 'Code' => 'TW', 'Name' => 'Taiwan, Province of China', ), 218 => array ( 'Code' => 'TJ', 'Name' => 'Tajikistan', ), 219 => array ( 'Code' => 'TZ', 'Name' => 'Tanzania, United Republic of', ), 220 => array ( 'Code' => 'TH', 'Name' => 'Thailand', ), 221 => array ( 'Code' => 'TL', 'Name' => 'Timor-Leste', ), 222 => array ( 'Code' => 'TG', 'Name' => 'Togo', ), 223 => array ( 'Code' => 'TK', 'Name' => 'Tokelau', ), 224 => array ( 'Code' => 'TO', 'Name' => 'Tonga', ), 225 => array ( 'Code' => 'TT', 'Name' => 'Trinidad and Tobago', ), 226 => array ( 'Code' => 'TN', 'Name' => 'Tunisia', ), 227 => array ( 'Code' => 'TR', 'Name' => 'Turkey', ), 228 => array ( 'Code' => 'TM', 'Name' => 'Turkmenistan', ), 229 => array ( 'Code' => 'TC', 'Name' => 'Turks and Caicos Islands', ), 230 => array ( 'Code' => 'TV', 'Name' => 'Tuvalu', ), 231 => array ( 'Code' => 'UG', 'Name' => 'Uganda', ), 232 => array ( 'Code' => 'UA', 'Name' => 'Ukraine', ), 233 => array ( 'Code' => 'AE', 'Name' => 'United Arab Emirates', ), 234 => array ( 'Code' => 'GB', 'Name' => 'United Kingdom', ), 235 => array ( 'Code' => 'US', 'Name' => 'United States', ), 236 => array ( 'Code' => 'UM', 'Name' => 'United States Minor Outlying Islands', ), 237 => array ( 'Code' => 'UY', 'Name' => 'Uruguay', ), 238 => array ( 'Code' => 'UZ', 'Name' => 'Uzbekistan', ), 239 => array ( 'Code' => 'VU', 'Name' => 'Vanuatu', ), 240 => array ( 'Code' => 'VE', 'Name' => 'Venezuela, Bolivarian Republic of', ), 241 => array ( 'Code' => 'VN', 'Name' => 'Viet Nam', ), 242 => array ( 'Code' => 'VG', 'Name' => 'Virgin Islands, British', ), 243 => array ( 'Code' => 'VI', 'Name' => 'Virgin Islands, U.S.', ), 244 => array ( 'Code' => 'WF', 'Name' => 'Wallis and Futuna', ), 245 => array ( 'Code' => 'EH', 'Name' => 'Western Sahara', ), 246 => array ( 'Code' => 'YE', 'Name' => 'Yemen', ), 247 => array ( 'Code' => 'ZM', 'Name' => 'Zambia', ), 248 => array ( 'Code' => 'ZW', 'Name' => 'Zimbabwe', ), );
    }

    private function ImmigrationCountryList()
    {
        return [['COUNTRY'=>'AFGHANISTAN','ABBREVIATION'=>'AFG'],['COUNTRY'=>'ALBANIA','ABBREVIATION'=>'ALB'],['COUNTRY'=>'ALGERIA','ABBREVIATION'=>'DZA'],['COUNTRY'=>'AMERICANSAMOA','ABBREVIATION'=>'ASM'],['COUNTRY'=>'ANDORRA','ABBREVIATION'=>'AND'],['COUNTRY'=>'ANGOLA','ABBREVIATION'=>'AGO'],['COUNTRY'=>'ANGUILLA','ABBREVIATION'=>'AIA'],['COUNTRY'=>'ANTARTICA','ABBREVIATION'=>'ATA'],['COUNTRY'=>'ANTIGUAANDBARBUDA','ABBREVIATION'=>'ATG'],['COUNTRY'=>'ARGENTINA','ABBREVIATION'=>'ARG'],['COUNTRY'=>'ARMENIA','ABBREVIATION'=>'ARM'],['COUNTRY'=>'ARUBA','ABBREVIATION'=>'ABW'],['COUNTRY'=>'AUSTRALIA','ABBREVIATION'=>'AUS'],['COUNTRY'=>'AUSTRIA','ABBREVIATION'=>'AUT'],['COUNTRY'=>'AZERBAIJAN','ABBREVIATION'=>'AZE'],['COUNTRY'=>'BAHAMAS','ABBREVIATION'=>'BHS'],['COUNTRY'=>'BAHRAIN','ABBREVIATION'=>'BHR'],['COUNTRY'=>'BANGLADESH','ABBREVIATION'=>'BGD'],['COUNTRY'=>'BARBADOS','ABBREVIATION'=>'BRB'],['COUNTRY'=>'BELARUS','ABBREVIATION'=>'BLR'],['COUNTRY'=>'BELGIUM','ABBREVIATION'=>'BEL'],['COUNTRY'=>'BELIZE','ABBREVIATION'=>'BLZ'],['COUNTRY'=>'BENIN','ABBREVIATION'=>'BEN'],['COUNTRY'=>'BERMUDA','ABBREVIATION'=>'BMU'],['COUNTRY'=>'BHUTAN','ABBREVIATION'=>'BTN'],['COUNTRY'=>'BOLIVIA','ABBREVIATION'=>'BOL'],['COUNTRY'=>'BOSNIAANDHERZEGOWINA','ABBREVIATION'=>'BIH'],['COUNTRY'=>'BOTSWANA','ABBREVIATION'=>'BWA'],['COUNTRY'=>'BOUVETISLAND','ABBREVIATION'=>'BVT'],['COUNTRY'=>'BRAZIL','ABBREVIATION'=>'BRA'],['COUNTRY'=>'BRITISHINDIANOCEANTERRITORY','ABBREVIATION'=>'IOT'],['COUNTRY'=>'BRUNEIDARUSSALAM','ABBREVIATION'=>'BRN'],['COUNTRY'=>'BULGARIA','ABBREVIATION'=>'BGR'],['COUNTRY'=>'BURKINAFASO','ABBREVIATION'=>'BFA'],['COUNTRY'=>'BURUNDI','ABBREVIATION'=>'BDI'],['COUNTRY'=>'CAMBODIA','ABBREVIATION'=>'KHM'],['COUNTRY'=>'CAMEROON','ABBREVIATION'=>'CMR'],['COUNTRY'=>'CANADA','ABBREVIATION'=>'CAN'],['COUNTRY'=>'CAPEVERDE','ABBREVIATION'=>'CPV'],['COUNTRY'=>'CAYMANISLANDS','ABBREVIATION'=>'CYM'],['COUNTRY'=>'CENTRALAFRICANREPUBLIC','ABBREVIATION'=>'CAF'],['COUNTRY'=>'CHAD','ABBREVIATION'=>'TCD'],['COUNTRY'=>'CHILE','ABBREVIATION'=>'CHL'],['COUNTRY'=>'CHINA','ABBREVIATION'=>'CHN'],['COUNTRY'=>'CHRISTMASISLAND','ABBREVIATION'=>'CXR'],['COUNTRY'=>'COCOS(KEELING)ISLANDS','ABBREVIATION'=>'CCK'],['COUNTRY'=>'COLOMBIA','ABBREVIATION'=>'COL'],['COUNTRY'=>'COMOROS','ABBREVIATION'=>'COM'],['COUNTRY'=>'CONGODEMOCRATICREPUBLIC(ZAIRE)','ABBREVIATION'=>'COD',],['COUNTRY'=>'CONGOPEOPLE\'SREPUBLIC','ABBREVIATION'=>'COG'],['COUNTRY'=>'COOKISLANDS','ABBREVIATION'=>'COK'],['COUNTRY'=>'COSTARICA','ABBREVIATION'=>'CRI'],['COUNTRY'=>'COTED\'IVOIRE','ABBREVIATION'=>'CIV'],['COUNTRY'=>'CROATIA(HRVATSKA)','ABBREVIATION'=>'HRV'],['COUNTRY'=>'CUBA','ABBREVIATION'=>'CUB'],['COUNTRY'=>'CYPRUS','ABBREVIATION'=>'CYP'],['COUNTRY'=>'CZECHREPUBLIC','ABBREVIATION'=>'CZE'],['COUNTRY'=>'DENMARK','ABBREVIATION'=>'DNK'],['COUNTRY'=>'DJIBOUTI','ABBREVIATION'=>'DJI'],['COUNTRY'=>'DOMINICA','ABBREVIATION'=>'DMA'],['COUNTRY'=>'DOMINICANREPUBLIC','ABBREVIATION'=>'DOM'],['COUNTRY'=>'EASTTIMOR','ABBREVIATION'=>'TLS'],['COUNTRY'=>'ECUADOR','ABBREVIATION'=>'ECU'],['COUNTRY'=>'EGYPT','ABBREVIATION'=>'EGY'],['COUNTRY'=>'ELSALVADOR','ABBREVIATION'=>'SLV'],['COUNTRY'=>'EQUATORIALGUINEA','ABBREVIATION'=>'GNQ'],['COUNTRY'=>'ERITREA','ABBREVIATION'=>'ERI'],['COUNTRY'=>'ESTONIA','ABBREVIATION'=>'EST'],['COUNTRY'=>'ETHIOPIA','ABBREVIATION'=>'ETH'],['COUNTRY'=>'FALKLANDISLANDS(MALVINAS)','ABBREVIATION'=>'FLK'],['COUNTRY'=>'FAROEISLANDS','ABBREVIATION'=>'FRO'],['COUNTRY'=>'FIJI','ABBREVIATION'=>'FJI'],['COUNTRY'=>'FINLAND','ABBREVIATION'=>'FIN'],['COUNTRY'=>'FRANCE','ABBREVIATION'=>'FRA'],['COUNTRY'=>'FRENCHGUIANA','ABBREVIATION'=>'GUF'],['COUNTRY'=>'FRENCHPOLYNESIA','ABBREVIATION'=>'PYF'],['COUNTRY'=>'FRENCHSOUTHERNANDANTARCTICLANDS','ABBREVIATION'=>'ATF'],['COUNTRY'=>'GABON','ABBREVIATION'=>'GAB'],['COUNTRY'=>'GAMBIA','ABBREVIATION'=>'GMB'],['COUNTRY'=>'GEORGIA','ABBREVIATION'=>'GEO'],['COUNTRY'=>'GERMANY','ABBREVIATION'=>'DEU'],['COUNTRY'=>'GHANA','ABBREVIATION'=>'GHA'],['COUNTRY'=>'GIBRALTAR','ABBREVIATION'=>'GIB'],['COUNTRY'=>'GREECE','ABBREVIATION'=>'GRC'],['COUNTRY'=>'GREENLAND','ABBREVIATION'=>'GRL'],['COUNTRY'=>'GRENADA','ABBREVIATION'=>'GRD'],['COUNTRY'=>'GUADELOUPE','ABBREVIATION'=>'GLP'],['COUNTRY'=>'GUAM','ABBREVIATION'=>'GUM'],['COUNTRY'=>'GUATEMALA','ABBREVIATION'=>'GTM'],['COUNTRY'=>'GUERNSEY','ABBREVIATION'=>'GGY'],['COUNTRY'=>'GUINEA','ABBREVIATION'=>'GIN'],['COUNTRY'=>'GUINEA-BISSAU','ABBREVIATION'=>'GNB'],['COUNTRY'=>'GUYANA','ABBREVIATION'=>'GUY'],['COUNTRY'=>'HAITI','ABBREVIATION'=>'HTI'],['COUNTRY'=>'HEARDANDMCDONALDISLANDS','ABBREVIATION'=>'HMD'],['COUNTRY'=>'HOLYSEE(VATICANCITYSTATE)','ABBREVIATION'=>'VAT'],['COUNTRY'=>'HONDURAS','ABBREVIATION'=>'HND'],['COUNTRY'=>'HONGKONG','ABBREVIATION'=>'HKG'],['COUNTRY'=>'HUNGARY','ABBREVIATION'=>'HUN'],['COUNTRY'=>'ICELAND','ABBREVIATION'=>'ISL'],['COUNTRY'=>'INDIA','ABBREVIATION'=>'IND'],['COUNTRY'=>'INDONESIA','ABBREVIATION'=>'IDN'],['COUNTRY'=>'IRAN(ISLAMICREPUBLIC)','ABBREVIATION'=>'IRN'],['COUNTRY'=>'IRAQ','ABBREVIATION'=>'IRQ'],['COUNTRY'=>'IRELAND','ABBREVIATION'=>'IRL'],['COUNTRY'=>'ISRAEL','ABBREVIATION'=>'ISR'],['COUNTRY'=>'ITALY','ABBREVIATION'=>'ITA'],['COUNTRY'=>'JAMAICA','ABBREVIATION'=>'JAM'],['COUNTRY'=>'JAPAN','ABBREVIATION'=>'JPN'],['COUNTRY'=>'JERSEY','ABBREVIATION'=>'JEY'],['COUNTRY'=>'JORDAN','ABBREVIATION'=>'JOR'],['COUNTRY'=>'KAZAKHSTAN','ABBREVIATION'=>'KAZ'],['COUNTRY'=>'KENYA','ABBREVIATION'=>'KEN'],['COUNTRY'=>'KIRIBATI','ABBREVIATION'=>'KIR'],['COUNTRY'=>'KOREADEMOCRATICPEOPLE\'SREPUBLIC','ABBREVIATION'=>'PRK',],['COUNTRY'=>'KOREA,REPUBLICOF','ABBREVIATION'=>'KOR',],['COUNTRY'=>'KUWAIT','ABBREVIATION'=>'KWT'],['COUNTRY'=>'KYRGYZSTAN','ABBREVIATION'=>'KGZ'],['COUNTRY'=>'LAOPEOPLE\'SDEMOCRATICREPUBLIC','ABBREVIATION'=>'LAO'],['COUNTRY'=>'LATVIA','ABBREVIATION'=>'LVA'],['COUNTRY'=>'LEBANON','ABBREVIATION'=>'LBN'],['COUNTRY'=>'LESOTHO','ABBREVIATION'=>'LSO'],['COUNTRY'=>'LIBERIA','ABBREVIATION'=>'LBR'],['COUNTRY'=>'LIBYANARABJAMAHIRIYA','ABBREVIATION'=>'LBY'],['COUNTRY'=>'LIECHTENSTEIN','ABBREVIATION'=>'LIE'],['COUNTRY'=>'LITHUANIA','ABBREVIATION'=>'LTU'],['COUNTRY'=>'LUXEMBOURG','ABBREVIATION'=>'LUX'],['COUNTRY'=>'MACAU','ABBREVIATION'=>'MAC'],['COUNTRY'=>'MACEDONIAFORMERYUGOSLAVREPUBLIC','ABBREVIATION'=>'MKD',],['COUNTRY'=>'MADAGASCAR','ABBREVIATION'=>'MDG'],['COUNTRY'=>'MALAWI','ABBREVIATION'=>'MWI'],['COUNTRY'=>'MALAYSIA','ABBREVIATION'=>'MYS'],['COUNTRY'=>'MALDIVES','ABBREVIATION'=>'MDV'],['COUNTRY'=>'MALI','ABBREVIATION'=>'MLI'],['COUNTRY'=>'MALTA','ABBREVIATION'=>'MLT'],['COUNTRY'=>'MAN,ISLEOF','ABBREVIATION'=>'IMN',],['COUNTRY'=>'MARSHALLISLANDS','ABBREVIATION'=>'MHL'],['COUNTRY'=>'MARTINIQUE','ABBREVIATION'=>'MTQ'],['COUNTRY'=>'MAURITANIA','ABBREVIATION'=>'MRT'],['COUNTRY'=>'MAURITIUS','ABBREVIATION'=>'MUS'],['COUNTRY'=>'MAYOTTE','ABBREVIATION'=>'MYT'],['COUNTRY'=>'MEXICO','ABBREVIATION'=>'MEX'],['COUNTRY'=>'MICRONESIA,FEDERATEDSTATES','ABBREVIATION'=>'FSM',],['COUNTRY'=>'MOLDOVAREPUBLIC','ABBREVIATION'=>'MDA',],['COUNTRY'=>'MONACO','ABBREVIATION'=>'MCO'],['COUNTRY'=>'MONGOLIA','ABBREVIATION'=>'MNG'],['COUNTRY'=>'MONTENEGRO','ABBREVIATION'=>'MNE'],['COUNTRY'=>'MONTSERRAT','ABBREVIATION'=>'MSR'],['COUNTRY'=>'MOROCCO','ABBREVIATION'=>'MAR'],['COUNTRY'=>'MOZAMBIQUE','ABBREVIATION'=>'MOZ'],['COUNTRY'=>'MYANMAR','ABBREVIATION'=>'MMR'],['COUNTRY'=>'NAMIBIA','ABBREVIATION'=>'NAM'],['COUNTRY'=>'NAURU','ABBREVIATION'=>'NRU'],['COUNTRY'=>'NEPAL','ABBREVIATION'=>'NPL'],['COUNTRY'=>'NETHERLANDS','ABBREVIATION'=>'NLD'],['COUNTRY'=>'NETHERLANDSANTILLES','ABBREVIATION'=>'ANT'],['COUNTRY'=>'NEWCALEDONIA','ABBREVIATION'=>'NCL'],['COUNTRY'=>'NEWZEALAND','ABBREVIATION'=>'NZL'],['COUNTRY'=>'NICARAGUA','ABBREVIATION'=>'NIC'],['COUNTRY'=>'NIGER','ABBREVIATION'=>'NER'],['COUNTRY'=>'NIGERIA','ABBREVIATION'=>'NGA'],['COUNTRY'=>'NIUE','ABBREVIATION'=>'NIU'],['COUNTRY'=>'NORFOLKISLAND','ABBREVIATION'=>'NFK'],['COUNTRY'=>'NORTHERNMARIANAISLANDS','ABBREVIATION'=>'MNP'],['COUNTRY'=>'NORWAY','ABBREVIATION'=>'NOR'],['COUNTRY'=>'OMAN','ABBREVIATION'=>'OMN'],['COUNTRY'=>'PAKISTAN','ABBREVIATION'=>'PAK'],['COUNTRY'=>'PALAU','ABBREVIATION'=>'PLW'],['COUNTRY'=>'PALESTINIANOCCUPIEDTERRITORY','ABBREVIATION'=>'PSE',],['COUNTRY'=>'PANAMA','ABBREVIATION'=>'PAN'],['COUNTRY'=>'PAPUANEWGUINEA','ABBREVIATION'=>'PNG'],['COUNTRY'=>'PARAGUAY','ABBREVIATION'=>'PRY'],['COUNTRY'=>'PERU','ABBREVIATION'=>'PER'],['COUNTRY'=>'PHILIPPINES','ABBREVIATION'=>'PHL'],['COUNTRY'=>'PITCAIRN','ABBREVIATION'=>'PCN'],['COUNTRY'=>'POLAND','ABBREVIATION'=>'POL'],['COUNTRY'=>'PORTUGAL','ABBREVIATION'=>'PRT'],['COUNTRY'=>'PUERTORICO','ABBREVIATION'=>'PRI'],['COUNTRY'=>'QATAR','ABBREVIATION'=>'QAT'],['COUNTRY'=>'REUNION','ABBREVIATION'=>'REU'],['COUNTRY'=>'ROMANIA','ABBREVIATION'=>'ROU'],['COUNTRY'=>'RUSSIANFEDERATION','ABBREVIATION'=>'RUS'],['COUNTRY'=>'RWANDA','ABBREVIATION'=>'RWA'],['COUNTRY'=>'SAINTHELENA','ABBREVIATION'=>'SHN'],['COUNTRY'=>'SAINTKITTSANDNEVIS','ABBREVIATION'=>'KNA'],['COUNTRY'=>'SAINTLUCIA','ABBREVIATION'=>'LCA'],['COUNTRY'=>'SAINTPIERREANDMIQUELON','ABBREVIATION'=>'SPM'],['COUNTRY'=>'SAINTVINCENT&GRENADINES','ABBREVIATION'=>'VCT'],['COUNTRY'=>'SAMOA','ABBREVIATION'=>'WSM'],['COUNTRY'=>'SANMARINO','ABBREVIATION'=>'SMR'],['COUNTRY'=>'SAOTOMEANDPRINCIPE','ABBREVIATION'=>'STP'],['COUNTRY'=>'SAUDIARABIA','ABBREVIATION'=>'SAU'],['COUNTRY'=>'SENEGAL','ABBREVIATION'=>'SEN'],['COUNTRY'=>'SERBIA','ABBREVIATION'=>'SRB'],['COUNTRY'=>'SEYCHELLES','ABBREVIATION'=>'SYC'],['COUNTRY'=>'SIERRALEONE','ABBREVIATION'=>'SLE'],['COUNTRY'=>'SINGAPORE','ABBREVIATION'=>'SGP'],['COUNTRY'=>'SLOVAKIA(SLOVAKREPUBLIC)','ABBREVIATION'=>'SVK'],['COUNTRY'=>'SLOVENIA','ABBREVIATION'=>'SVN'],['COUNTRY'=>'SOLOMONISLANDS','ABBREVIATION'=>'SLB'],['COUNTRY'=>'SOMALIA','ABBREVIATION'=>'SOM'],['COUNTRY'=>'SOUTHAFRICA','ABBREVIATION'=>'ZAF'],['COUNTRY'=>'SOUTHGEORGIA&SOUTHSANDWICHISLANDS','ABBREVIATION'=>'SGS'],['COUNTRY'=>'SPAIN','ABBREVIATION'=>'ESP'],['COUNTRY'=>'SRILANKA','ABBREVIATION'=>'LKA'],['COUNTRY'=>'SUDAN','ABBREVIATION'=>'SDN'],['COUNTRY'=>'SURINAME','ABBREVIATION'=>'SUR']
        ,['COUNTRY'=>'SVALBARD&JANMAYENISLANDS','ABBREVIATION'=>'SJM'],['COUNTRY'=>'SWAZILAND','ABBREVIATION'=>'SWZ'],['COUNTRY'=>'SWEDEN','ABBREVIATION'=>'SWE'],['COUNTRY'=>'SWITZERLAND','ABBREVIATION'=>'CHE'],['COUNTRY'=>'SYRIA','ABBREVIATION'=>'SYR'],['COUNTRY'=>'TAIWAN','ABBREVIATION'=>'TWN'],['COUNTRY'=>'TAJIKISTAN','ABBREVIATION'=>'TJK'],['COUNTRY'=>'THAILAND','ABBREVIATION'=>'THA'],['COUNTRY'=>'TOGO','ABBREVIATION'=>'TGO'],['COUNTRY'=>'TOKELAU','ABBREVIATION'=>'TKL'],['COUNTRY'=>'TONGA','ABBREVIATION'=>'TON'],['COUNTRY'=>'TRINIDADANDTOBAGO','ABBREVIATION'=>'TTO'],['COUNTRY'=>'TUNISIA','ABBREVIATION'=>'TUN'],['COUNTRY'=>'TURKEY','ABBREVIATION'=>'TUR'],['COUNTRY'=>'TURKMENISTAN','ABBREVIATION'=>'TKM'],['COUNTRY'=>'TURKSANDCAICOSISLANDS','ABBREVIATION'=>'TCA'],['COUNTRY'=>'TUVALU','ABBREVIATION'=>'TUV'],['COUNTRY'=>'UGANDA','ABBREVIATION'=>'UGA'],['COUNTRY'=>'UKRAINE','ABBREVIATION'=>'UKR'],['COUNTRY'=>'UNITEDARABEMIRATES','ABBREVIATION'=>'ARE'],['COUNTRY'=>'UKCITIZEN','ABBREVIATION'=>'GBR'],['COUNTRY'=>'UNITEDSTATESOFAMERICA','ABBREVIATION'=>'USA'],['COUNTRY'=>'URUGUAY','ABBREVIATION'=>'URY'],['COUNTRY'=>'UZBEKISTAN','ABBREVIATION'=>'UZB'],['COUNTRY'=>'VANUATU','ABBREVIATION'=>'VUT'],['COUNTRY'=>'VENEZUELA','ABBREVIATION'=>'VEN'],['COUNTRY'=>'VIETNAM','ABBREVIATION'=>'VNM'],['COUNTRY'=>'VIRGINISLANDS(BRITISH)','ABBREVIATION'=>'VGB'],['COUNTRY'=>'VIRGINISLANDS(U.S.)','ABBREVIATION'=>'VIR'],['COUNTRY'=>'WALLISANDFUTUNAISLANDS','ABBREVIATION'=>'WLF'],['COUNTRY'=>'WESTERNSAHARA','ABBREVIATION'=>'ESH'],['COUNTRY'=>'YEMEN','ABBREVIATION'=>'YEM'],['COUNTRY'=>'YUGOSLAVIA','ABBREVIATION'=>'YUG'],['COUNTRY'=>'ZAMBIA','ABBREVIATION'=>'ZMB'],['COUNTRY'=>'ZIMBABWE','ABBREVIATION'=>'ZWE'],['COUNTRY'=>'ALANDISLANDS','ABBREVIATION'=>'ALA'],['COUNTRY'=>'BONAIRE,SINTEUSTATIUSANDSABA','ABBREVIATION'=>'BES',],['COUNTRY'=>'SAINTBARTHELEMY','ABBREVIATION'=>'BLM'],['COUNTRY'=>'CURACAO','ABBREVIATION'=>'CUW'],['COUNTRY'=>'SAINTMARTIN','ABBREVIATION'=>'MAF'],['COUNTRY'=>'SOUTHSUDAN','ABBREVIATION'=>'SSD'],['COUNTRY'=>'SINTMAARTEN(DUTCHPART)','ABBREVIATION'=>'SXM'],['COUNTRY'=>'UNITEDSTATESMINOROUTLYINGISLANDS','ABBREVIATION'=>'UMI'],['COUNTRY'=>'UK-DEPENDENTTERRITORIESCITIZEN','ABBREVIATION'=>'GBD'],['COUNTRY'=>'UK-NATIONAL(OVERSEAS)','ABBREVIATION'=>'GBN'],['COUNTRY'=>'UK-OVERSEASCITIZEN','ABBREVIATION'=>'GBO'],['COUNTRY'=>'UNITEDNATIONSORGANIZATION','ABBREVIATION'=>'UNO'],['COUNTRY'=>'UNSPECIALIZEDAGENCYOFFICIAL','ABBREVIATION'=>'UNA'],['COUNTRY'=>'STATELESS','ABBREVIATION'=>'XXA'],['COUNTRY'=>'REFUGEE','ABBREVIATION'=>'XXB'],['COUNTRY'=>'REFUGEE(NON-CONVENTION)','ABBREVIATION'=>'XXC'],['COUNTRY'=>'UNSPECIFIED/UNKNOWN','ABBREVIATION'=>'XXX'],['COUNTRY'=>'UK-PROTECTEDPERSON','ABBREVIATION'=>'GBP'],['COUNTRY'=>'UK-SUBJECT','ABBREVIATION'=>'GBS'],['COUNTRY'=>'AFRICANDEVELOPMENTBANK','ABBREVIATION'=>'XBA'],['COUNTRY'=>'AFRICANEXPORT–IMPORTBANK','ABBREVIATION'=>'XIM'],['COUNTRY'=>'CARIBBEANCOMMUNITYORONEOFITSEMISSARIES','ABBREVIATION'=>'XCC'],['COUNTRY'=>'COMMONMARKETFOREASTERNANDSOUTHERNAFRICA','ABBREVIATION'=>'XCO'],['COUNTRY'=>'ECONOMICCOMMUNITYOFWESTAFRICANSTATES','ABBREVIATION'=>'XEC'],['COUNTRY'=>'INTERNATIONALCRIMINALPOLICEORGANIZATION','ABBREVIATION'=>'XPO'],['COUNTRY'=>'SOVEREIGNMILITARYORDEROFMALTA','ABBREVIATION'=>'XOM']];
    }

}
