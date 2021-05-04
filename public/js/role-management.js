// document.querySelector("#user-role").addEventListener("click", function(e) {
//     e.preventDefault();
//     document.querySelector("#user-role-text").value = this.value;
// });

var RightArry = [];
var RoleID = 0;
var JKYCObject; //= JSON.parse('{"Row":[{"ID": 10, "Description":"Agent", "ParentID":0},{"ID": 1001, "Description":"Agent List", "ParentID":10},{"ID": 1002, "Description":"Add Agent", "ParentID":10},{"ID": 11, "Description":"Staff Agent", "ParentID":0},{"ID": 1101, "Description":"Staff Agent List", "ParentID":11},{"ID": 1102, "Description":"Add Staff Agent", "ParentID":11},{"ID": 110201, "Description":"Add Child", "ParentID":1102}]}')

$.ajax({
    url: "/permissions/user/rights",
    method: "GET"
}).done(function(response) {
    //console.log(response);
    JKYCObject = response;
    AddTreeView("divekycTreview");
});

function removeArryItem(arr, item) {
    for (var i = arr.length; i--; ) {
        if (arr[i].Right == item) {
            arr.splice(i, 1);
        }
    }
}

function AddTreeView(HElement) {
    const result = JKYCObject.Row.filter(function(item) {
        return item.ParentID == 0;
    });

    var ht = "<ul>";
    for (x = 0; x < result.length; x++) {
        ht = ht + '<li id="lst_' + result[x].ID.toString() + '">';
        ht =
            ht +
            '<input onchange="CheckingRight(this)" value="' +
            result[x].ID.toString() +
            '" type="checkbox" id="trv_' +
            result[x].ID.toString() +
            '"><label class="ml-2" for="trv_' +
            result[x].ID.toString() +
            '">' +
            result[x].Description +
            "</label></li>";
    }
    ht = ht + "</ul>";
    $("#" + HElement.toString()).html(ht); // alert(JKYCObject);
    //console.log(result);
    for (y = 0; y < result.length; y++) {
        //console.log(result[y].ID)
        AddTreeNode(result[y].ID);
    }
}

function AddTreeNode(Parent) {
    const resultChild = JKYCObject.Row.filter(function(item) {
        return item.ParentID == Parent;
    });
    if (resultChild.length == 0) {
        return;
    }

    var ht = "<ul>";
    for (k = 0; k < resultChild.length; k++) {
        ht = ht + '<li id="lst_' + resultChild[k].ID.toString() + '">';
        ht =
            ht +
            '<input onchange="CheckingRight(this)" value="' +
            resultChild[k].ID.toString() +
            '" type="checkbox" id="trv_' +
            resultChild[k].ID.toString() +
            '"><label class="ml-2" for="trv_' +
            resultChild[k].ID.toString() +
            '">' +
            resultChild[k].Description +
            "</label></li>";
    }
    ht = ht + "</ul>";
    $("#lst_" + Parent.toString()).append(ht);

    for (i = 0; i < resultChild.length; i++) {
        //console.log(resultChild[i].ID);
        AddTreeNode(resultChild[i].ID);
    }
    //
}
function CheckingRight(e) {
    var x = 0;
    if (e.checked == true) {
        RightArry.push({ Right: e.value });
    } else {
        removeArryItem(RightArry, e.value);
    }

    for (x = 0; x < JKYCObject.Row.length; x++) {
        // console.log(JKYCObject.Row[x].ParentID)
        if (e.value == JKYCObject.Row[x].ParentID) {
            var el = document.getElementById(
                "trv_" + JKYCObject.Row[x].ID.toString()
            );
            el.checked = e.checked;
            CheckingRight(el);
        }
    }
}
function clearRightSelect() {
    RightArry = [];
    for (x = 0; x < JKYCObject.Row.length; x++) {
        try {
            var el = document.getElementById(
                "trv_" + JKYCObject.Row[x].ID.toString()
            );
            el.checked = false;
        } catch {}
    }
}

function RoleSelected(e) {
    if (e.checked == true) {
        clearRightSelect();
        RoleID = e.value;
        $.ajax({
            url: "/permissions/user/rights/" + e.value.toString(),
            method: "GET"
        }).done(function(response) {
            for (i = 0; i < response.length; i++) {
                var el = document.getElementById(
                    "trv_" + response[i].RightID.toString()
                );
                RightArry.push({ Right: response[i].RightID });
                el.checked = true;
            }
        });
    }
}

document
    .querySelector("#saveUserRoleRights")
    .addEventListener("click", function(e) {
        e.preventDefault(e);
        var Data = {
            Role: RoleID,
            Rights: RightArry
        };

        $.ajax({
            url: "/permissions/user/rights",
            method: "POST",
            //dataType: "json",
            data: Data
        }).done(function(response) {
            //console.log(response);
            clearRightSelect();
            var el = document.getElementById("role_" + RoleID.toString());
            el.checked = false;
            RoleID = 0;
        });
    });
