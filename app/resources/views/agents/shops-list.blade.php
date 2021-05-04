@extends('layout.app')

@section('content')

    <!-- Main section-->
    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">
            @include('layout.flash-messages')
            <div class="row">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <div class="lead text-bold text-primary">Add New Shop</div>
                        </div>
                        <div class="card-body">
                            <form action="{{ action('KYA\AgentsController@AgentShopSave') }}" method="post">
                                @csrf
                                <input type="hidden" name="agentID" value={{$agent['AgentID']}}>
                                <div class="form-row">
                                    <div class="col-5">
                                        <label class="text-bold" for="exampleInputEmail1">SHOP NAME</label>
                                        <input name="shopName" type="text" class="form-control" id="shop-name" placeholder="Enter Shop Name">
                                    </div>
                                    <div class="col-2">
                                        <label class="text-bold" for="exampleInputEmail1">SHOP CODE</label>
                                        <input name="shopCode" type="text" class="form-control" id="shop-code" placeholder="Enter Shop Code">
                                    </div>
                                    <div class="col-3">
                                        <div class="form-row">
                                            <div class="col-md-12 col-xs-12 mb-3">
                                                <label class="text-bold" for="exampleInputEmail1">TERRITORY</label>
                                                <select class="form-control" name="territory"  id="territory-dropdown"></select>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="col-2 mt-4">
                                        <button id="addNewShop" type="submit" class="btn btn-primary btn-lg"> Add Shop</button>
                                    </div>
                                </div>
                            </form>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <div class="lead text-bold text-primary">My Shops</div>
                        </div>

                        <div class="card-body">
                            @if ($shops)
                                <table class="table table-striped table-hover w-100" id="datatable1">
                                    <thead>
                                        <tr>
                                            <th data-priority="1">Name title</th>
                                            <th>Code</th>
                                            <th>Zone</th>
                                            <th>Region</th>
                                            <th>Terrirtory</th>
                                            <th data-priority="2">Admin</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        @foreach ($shops as $item)
                                            <tr>
                                                <td>
                                                    {{$item['ShopName']}}

                                                </td>
                                                <td>
                                                    {{$item['ShopCode']}}
                                                </td>
                                                <td>
                                                    {{$item['ZoneName']}}
                                                </td>
                                                <td>
                                                    {{$item['RegionName']}}
                                                </td>
                                                <td>
                                                    {{$item['TerritoryName']}}
                                                </td>
                                                <td>
                                                    {{-- <button class="btn btn-warning btn-detail open_modal" value="{{$item}}">Edit</button> --}}
                                                </td>
                                            </tr>
                                        @endforeach

                                    </tbody>
                                </table>
                            @else
                            <h3 class="text text-info lead"><strong>Looks like there are no any Shops yet. Add one using the above form !</strong></h3>
                            @endif

                        </div>
                    </div>
                </div>

            </div>
        </div>
    </section>

@endsection

@section('scripts')
    {{-- @include('agents.shop-edit-modal') --}}
<script>
    $("#territory-dropdown").html(
        "<option value=''>--select Territory--</option>"
    );
    var settings = {
        async: true,
        crossDomain: true,
        url: "/territory/" + {{$agent['RegionID']}},
        method: "GET"
    };

    $.ajax(settings).done(function(response) {
        console.log(response);
        for (x = 0; x < response.length; x++) {
            var ID = response[x]["ID"];
            var Data = response[x]["Description"];
            $("#territory-dropdown").append(
                '<option value="' + ID.toString() + '">' + Data + "</option>"
            );
        }

    });

    // $(document).on('click','.open_modal',function(){
    //     var url = "domain.com/yoururl";
    //     var tour_id= $(this).val();
    //     // $.get(url + '/' + tour_id, function (data) {
    //     //     //success data
    //         console.log(tour_id);
    //         // $('#tour_id').val(data.id);
    //         // $('#name').val(data.name);
    //         // $('#details').val(data.details);
    //         // $('#btn-save').val("update");
    //         // $('#myModal').modal('show');
    //     });
    //});


</script>

@endsection
