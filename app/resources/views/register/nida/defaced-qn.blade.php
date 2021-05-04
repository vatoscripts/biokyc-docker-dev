<!---Place for device register modal-->
<div class="modal fade" data-keyboard="false" data-backdrop="static" id="defaced-customer-question" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header alert-danger" style="height:40px;"> DEFACED CUSTOMER REGISTRATION
                <button class="close" data-dismiss="modal" style="margin-top:-25px;">&times;</button>
            </div>

            <blockquote id="flash-message" class="p-2 text text-danger h4 ml-3"></blockquote>

            <div id="defacedCustomerBlock" class="modal-body p-3">
                <form method="post" action="{{ action('KYC\KYCController@getDefacedAnswer') }}" class="mb-3" id="defacedCustomerForm" novalidate>
                    @csrf

                    <input type="hidden" name="QuestionCode" id="QuestionCode">

                    <div class="form-group">
                        <p id="defaced_qn" class="lead text-primary"></p>
                        <input id="defaced_answer" name="defaced_answer" class="form-control" type="text" placeholder="Enter answer">
                    </div>

                    <div class="modal-footer">
                        <button id="cancel" class="btn btn-danger" data-dismiss="modal"> Cancel</button>
                        <button id="defacedRegisterBtn" type="submit" class="btn btn-primary"><span class="fa fa-save"></span> Answer</button>
                    </div>
                </form>
            </div>

        </div>
    </div>
</div>
<!----end device register modal-->


