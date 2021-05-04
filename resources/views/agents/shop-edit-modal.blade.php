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
                                    <input name="shopName" value="{{$shop['ShopName']}}" type="text" class="form-control" id="shop-name" placeholder="Enter Shop Name">
                                    </div>
                                    <div class="col-2">
                                        <label class="text-bold" for="exampleInputEmail1">SHOP CODE</label>
                                        <input name="shopCode" value="{{$shop['ShopCode']}}" type="text" class="form-control" id="shop-code" placeholder="Enter Shop Code">
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
