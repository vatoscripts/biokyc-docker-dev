@extends('layout.app')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">
            <h4 class="content-heading">
                <div>Dashboard
                    <p class="lead mt-2">Welcome to eKYC Biometric Portal: <strong>{{$user['Surname']}}, {{$user['FirstName']}}</strong> </p>
                </div>
            </h4>
            <!-- START cards box-->
            @include('layout.flash-messages')
            <div class="row">
                <div class="col-xl-3 col-md-6">
                    <!-- START card-->
                    <div class="card flex-row align-items-center align-items-stretch border-0">
                        <div class="col-4 d-flex align-items-center bg-info-dark justify-content-center rounded-left">
                            <em class="icon-bell fa-3x"></em>
                        </div>
                        <div class="col-8 py-3 bg-primary rounded-right">
                            <div class="h2 mt-0">{{ $total[0]['TotalReg'] }}</div>
                            <div class="text-uppercase">All Registration</a>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-xl-3 col-md-6">
                    <!-- START card-->
                    <div class="card flex-row align-items-center align-items-stretch border-0">
                        <div class="col-4 d-flex align-items-center bg-purple-dark justify-content-center rounded-left">
                            <em class="icon-check fa-3x"></em>
                        </div>
                        <div class="col-8 py-3 bg-green-light rounded-right">
                            <div class="h2 mt-0">{{ $total[0]['TodayTotal'] }}

                            </div>
                            <div class="text-uppercase">Current Regs</div>
                        </div>
                    </div>
                </div>
                <div class="col-xl-3 col-lg-6 col-md-12">
                    <!-- START card-->
                    <div class="card flex-row align-items-center align-items-stretch border-0">
                        <div class="col-4 d-flex align-items-center bg-green-dark justify-content-center rounded-left">
                            <em class="icon-equalizer fa-3x"></em>
                        </div>
                        <div class="col-8 py-3 bg-danger-light rounded-right">
                            <div class="h2 mt-0">{{ $total[0]['IcapTotal'] }}
                                <small></small>
                            </div>
                            <div class="text-uppercase">Failed ICAP</div>
                        </div>
                    </div>
                </div>

                <div class="col-xl-3 col-lg-6 col-md-12">
                    <!-- START card-->
                    <div class="card flex-row align-items-center align-items-stretch border-0">
                        <div class="col-4 d-flex align-items-center bg-green-dark justify-content-center rounded-left">
                            <em class="icon-equalizer fa-3x"></em>
                        </div>
                        <div class="col-8 py-3 bg-danger-light rounded-right">
                            <div class="h2 mt-0">{{ $total[0]['NidaTotal'] }}
                                <small></small>
                            </div>
                            <div class="text-uppercase">Failed VERIFICATION</div>
                        </div>
                    </div>
                </div>

            </div>
            <!-- END cards box-->
            <div class="row">
                <!-- START dashboard main content-->
                <div class="col-xl-9">

                    <div class="row">
                        <div class="col-xl-12">

                            <!-- DATATABLE DEMO 2-->
                            <div class="card">
                                <div class="card-body">
                                    <table class="table table-striped my-4 w-100" id="datatable2">
                                        <thead>
                                            <tr>
                                                <th data-priority="1">Registration Date</th>
                                                <th>New Registration

                                                </th>
                                                <th>Re Registration</th>
                                                <th class="sort-numeric">Total Success</th>
                                                <th class="sort-alpha" data-priority="2">Total Failed</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                        @foreach ($regSummary as $item)

                                            <tr class="gradeX">
                                                <td>{{ date('Y-m-d h:i:s', strtotime($item['RegDate'])) }}</td>
                                                <td>{{ $item['NewReg'] }}</td>
                                                <td>{{ $item['ReReg'] }}</td>
                                                <td>{{ $item['Total'] }}</td>
                                                <td>{{ $item['Fail'] }}</td>
                                            </tr>

                                        @endforeach
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                            <!-- DATATABLE-->
                        </div>
                    </div>

                </div>
                <!-- END dashboard main content-->
                <!-- START dashboard sidebar-->
                <aside class="col-xl-3">
                    <!-- START loader widget-->

                    <!-- END loader widget-->
                    <!-- START messages and activity-->

                    {{-- @foreach ($recents as $w)
                        @foreach ($w as $k)

                                {{ print_r($k) }}

                        @endforeach
                    @endforeach --}}

                    <div class="card card-default">
                        <div class="card-header">
                            <div class="card-title">Recent Registration Activities</div>
                        </div>


                        <!-- START list group-->
                        <div class="list-group">

                            <!-- START list group item-->
                            @foreach($recents as $item)
                            <div class="list-group-item">
                                <div class="media">
                                    <div class="align-self-start mr-2">
                                        <span class="fa-stack">
                                <em class="fa fa-circle fa-stack-2x text-purple"></em>
                                <em class="fas fa-cloud-upload-alt fa-stack-1x fa-inverse text-white"></em>
                                </span>
                                    </div>

                                    <div class="media-body text-truncate">
                                        <p class="mb-1">
                                            <span class="text-danger text-small" >{{$item['FullName'] }}</span>
                                        </p>
                                        <br/>
                                        <small>
                                            <span><strong>Number:</strong> {{$item['PhoneNo'] }}</span><br/>
                                            <span><strong>FRegtime:</strong> {{date('Y-m-d h:i:s', strtotime($item['RegDate'])) }}</span><br/>
                                            <span><strong>Status:</strong> {{$item['Status'] }}</span><br/>
                                            <span><strong>Type:</strong> {{ $item['RegType'] =='re-Reg'?'Re-Reg':'New' }}</span><br/>
                                        </small>
                                        </p>
                                    </div>
                                </div>
                            </div>
                            @endforeach
                        </div>
                        <!-- END list group-->
                        <!-- START card footer-->
                        <div class="card-footer">
                            <a class="text-sm">Last 5 record shown</a>
                        </div>
                        <!-- END card-footer-->
                    </div>

                    <!---=====TOP PERFORMER FOR ADMIN ONLY-->
                    {{-- <div class="card card-default">
                        <div class="card-header">
                            <div class="card-title">Top Agents</div>
                            <div class="media-body text-truncate">
                                <p class="mb-1">
                                    <a class="text-purple m-0" href="#">Activities #2</a>
                                </p>
                                <br/>
                                <small>
                            <span>Customer Name: John Doe</span><br/>
                            <span>Registration sent time:04:31 PM 7/5/2019</span><br/>
                            <span>Status: Success FREG</span><br/>
                        </small>
                                </p>
                            </div>
                        </div>
                        <div class="card-header">
                            <div class="card-title">Top Agents</div>
                            <div class="media-body text-truncate">
                                <p class="mb-1">
                                    <a class="text-purple m-0" href="#">Activities #2</a>
                                </p>
                                <br/>
                                <small>
                            <span>Customer Name: John Doe</span><br/>
                            <span>Registration sent time:04:31 PM 7/5/2019</span><br/>
                            <span>Status: Success FREG</span><br/>
                        </small>
                                </p>
                            </div>
                        </div>
                    </div> --}}
                    <!-- END messages and activity-->
                    {{-- <div class="card card-default">
                        <div class="card-body">

                            <div class="text-info">Average Daily KPI</div>
                            <div class="text-center py-4">
                                <div class="easypie-chart easypie-chart-lg" data-easypiechart data-percent="70" data-animate="{&quot;duration&quot;: &quot;800&quot;, &quot;enabled&quot;: &quot;true&quot;}" data-bar-color="#23b7e5" data-track-Color="rgba(200,200,200,0.4)" data-scale-Color="false"
                                    data-line-width="10" data-line-cap="round" data-size="145">
                                    <span>99.5%</span>
                                </div>
                            </div>
                            <div class="text-center" data-sparkline="" data-bar-color="#23b7e5" data-height="30" data-bar-width="5" data-bar-spacing="2" data-values="5,4,8,7,8,5,4,6,5,5,9,4,6,3,4,7,5,4,7"></div>
                        </div>

                    </div> --}}
                </aside>
                <!-- END dashboard sidebar-->
            </div>

        </div>

    </section>

@endsection
