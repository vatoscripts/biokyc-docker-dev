@extends('layout.app')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">

            <div class="content-heading">
                <div>Agent Staff Reports
                    <p class="lead mt-2">KYA Reports: Agent Staff per Registrations.</p>
                </div>
            </div>

            @include('layout.flash-messages')

                <div class="row">
                    <!-- START dashboard main content-->
                    <div class="col-xl-12">
                        <div class="card">
                            <div class="card-header">Products in order</div>
                            <div class="table-responsive">
                               <table class="table table-hover table-bordered table-striped">
                                  <thead>
                                     <tr>
                                        <th>Username</th>
                                        <th>Fullname</th>
                                        <th>Shop Name</th>
                                        <th>Today</th>
                                        <th class="text-center">Status</th>
                                        <th>Total</th>
                                     </tr>
                                  </thead>
                                  <tbody>
                                     <tr>
                                        <td><a href="">Product #123</a></td>
                                        <td>$ 100.00</td>
                                        <td>5</td>
                                        <td>21%</td>
                                        <td class="text-center"><span class="badge badge-success">In Stock</span></td>
                                        <td>$ 605.00</td>
                                     </tr>
                                     <tr>
                                        <td><a href="">Product #123</a></td>
                                        <td>$ 100.00</td>
                                        <td>5</td>
                                        <td>21%</td>
                                        <td class="text-center"><span class="badge badge-success">In Stock</span></td>
                                        <td>$ 605.00</td>
                                     </tr>
                                     <tr>
                                        <td><a href="">Product #123</a></td>
                                        <td>$ 100.00</td>
                                        <td>5</td>
                                        <td>21%</td>
                                        <td class="text-center"><span class="badge badge-warning">N/A</span></td>
                                        <td>$ 605.00</td>
                                     </tr>
                                     <tr>
                                        <td><a href="">Product #123</a></td>
                                        <td>$ 100.00</td>
                                        <td>5</td>
                                        <td>21%</td>
                                        <td class="text-center"><span class="badge badge-danger">Out Stock</span></td>
                                        <td>$ 605.00</td>
                                     </tr>
                                     <tr>
                                        <td><a href="">Product #123</a></td>
                                        <td>$ 100.00</td>
                                        <td>5</td>
                                        <td>21%</td>
                                        <td class="text-center"><span class="badge badge-success">In Stock</span></td>
                                        <td>$ 605.00</td>
                                     </tr>
                                  </tbody>
                               </table>
                            </div>
                         </div>
                    </div>
                    <!-- END dashboard main content-->
                </div>
        </div>

    </section>
@endsection

@section('scripts')

<script src="{{ asset('js/agentstaff.js') }}"></script>
<script src="{{ asset('js/agentstaffLocation.js') }}"></script>
@endsection

