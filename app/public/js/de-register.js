$(document).ready(function() {
	document.querySelector("#deRegBtn1").addEventListener("click", function() {
	    $("#fingerData").val(CapturedData);
	    $("#fingerCode").val(CapturedFinger);
	});
});
