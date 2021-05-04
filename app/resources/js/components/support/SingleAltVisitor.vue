<template>
    <div>
        <div class="clearfix"></div>
        <div
            v-show="message"
            class="alert alert-warning alert-block mt-1 text-center"
        >
            <span class="h3">{{ message }}</span>
        </div>
        <div class="row vld-parent" ref="formContainer">
            <div class="col-lg-4">
                <div class="card card-default">
                    <div class="card-header">
                        <div class="text-bold card-title text-center">
                            Customer Portait
                        </div>
                    </div>
                    <div class="card-body text-center">
                        <div class="py-4">
                            <img
                                class="img-fluid  img-thumbnail"
                                :src="'data:image/png;base64,' + reg.Photo"
                                alt="Contact"
                            />
                        </div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <div class="text-bold card-title text-center">
                            Customer Signature
                        </div>
                    </div>
                    <div class="card-body">
                        <img
                            class="img-fluid rounded-circle img-thumbnail"
                            :src="'data:image/png;base64,' + reg.Signature"
                            alt="Contact"
                        />
                    </div>
                </div>
            </div>
            <div class="col-lg-8">
                <div class="card card-default">
                    <div class="card-header">
                        <div class="text-bold card-title text-center">
                            Customer Details
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="row py-4 justify-content-center">
                            <div class="col-12 col-sm-10">
                                <form
                                    class="form-horizontal"
                                    ref="reDetailsform"
                                >
                                    <div class="form-group row">
                                        <label
                                            class="text-bold col-4 col-form-label text-right"
                                            for="inputContact1"
                                            >First Name</label
                                        >
                                        <div class="col-8">
                                            <input
                                                class="form-control"
                                                name="firstName"
                                                type="text"
                                                placeholder=""
                                                v-model="reg.FirstName"
                                            />
                                        </div>
                                        <div
                                            v-if="errors && errors.FirstName"
                                            class="text-danger"
                                        >
                                            {{ errors.FirstName[0] }}
                                        </div>
                                    </div>
                                    <div class="form-group row">
                                        <label
                                            class="text-bold col-4 col-form-label text-right"
                                            for="inputContact1"
                                            >Middle Name</label
                                        >
                                        <div class="col-8">
                                            <input
                                                class="form-control"
                                                name="middleName"
                                                type="text"
                                                placeholder=""
                                                :value="reg.MiddleName"
                                            />
                                        </div>
                                        <div
                                            v-if="errors && errors.MiddleName"
                                            class="text-danger"
                                        >
                                            {{ errors.MiddleName[0] }}
                                        </div>
                                    </div>
                                    <div class="form-group row">
                                        <label
                                            class="text-bold col-4 col-form-label text-right"
                                            for="inputContact1"
                                            >Last Name</label
                                        >
                                        <div class="col-8">
                                            <input
                                                class="form-control"
                                                name="lastName"
                                                type="text"
                                                placeholder=""
                                                :value="reg.Surname"
                                            />
                                        </div>
                                        <div
                                            v-if="errors && errors.Surname"
                                            class="text-danger"
                                        >
                                            {{ errors.Surname[0] }}
                                        </div>
                                    </div>
                                    <div class="form-group row">
                                        <label
                                            class="text-bold col-4 col-form-label text-right"
                                            for="inputContact2"
                                            >Passport Number</label
                                        >
                                        <div class="col-8">
                                            <input
                                                class="form-control"
                                                name="idNumber"
                                                type="text"
                                                :value="reg.IDNumber"
                                            />
                                        </div>
                                        <div
                                            v-if="errors && errors.IDNumber"
                                            class="text-danger"
                                        >
                                            {{ errors.IDNumber[0] }}
                                        </div>
                                    </div>
                                    <div class="form-group row">
                                        <label
                                            class="text-bold col-4 col-form-label text-right"
                                            for="inputContact2"
                                            >Passport Expiry Date</label
                                        >
                                        <div class="col-8">
                                            <input
                                                class="form-control"
                                                name="expiryDate"
                                                type="text"
                                                :value="reg.PassportExpiryDate"
                                            />
                                        </div>
                                        <div
                                            v-if="
                                                errors &&
                                                    errors.PassportExpiryDate
                                            "
                                            class="text-danger"
                                        >
                                            {{ errors.PassportExpiryDate[0] }}
                                        </div>
                                    </div>
                                    <div class="form-group row">
                                        <label
                                            class="text-bold col-4 col-form-label text-right"
                                            for="inputContact3"
                                            >Msisdn</label
                                        >
                                        <div class="col-8">
                                            <input
                                                class="form-control"
                                                name="msisdn"
                                                type="text"
                                                :value="reg.MSISDN"
                                                readonly
                                            />
                                        </div>
                                    </div>
                                    <div class="form-group row">
                                        <label
                                            class="text-bold col-4 col-form-label text-right"
                                            for="inputContact4"
                                            >Gender</label
                                        >
                                        <div class="col-8">
                                            <input
                                                class="form-control"
                                                name="gender"
                                                type="text"
                                                :value="reg.Gender"
                                            />
                                        </div>
                                        <div
                                            v-if="errors && errors.Gender"
                                            class="text-danger"
                                        >
                                            {{ errors.Gender[0] }}
                                        </div>
                                    </div>
                                    <div class="form-group row">
                                        <label
                                            class="text-bold col-4 col-form-label text-right"
                                            for="inputContact5"
                                            >Date of Birth</label
                                        >
                                        <div class="col-8">
                                            <input
                                                class="form-control"
                                                name="dob"
                                                type="text"
                                                :value="reg.Dob"
                                            />
                                        </div>
                                    </div>
                                    <div class="form-group row">
                                        <label
                                            class="text-bold col-4 col-form-label text-right"
                                            for="inputContact6"
                                            >Nationality</label
                                        >
                                        <div class="col-8">
                                            <input
                                                class="form-control"
                                                name="nationality"
                                                type="text"
                                                :value="reg.Nationality"
                                                readonly
                                            />
                                        </div>
                                    </div>
                                    <div class="form-group row">
                                        <label
                                            class="text-bold col-4 col-form-label text-right"
                                            for="inputContact7"
                                            >Region</label
                                        >
                                        <div class="col-8">
                                            <input
                                                class="form-control"
                                                name="region"
                                                type="text"
                                                :value="reg.ResidentRegion"
                                            />
                                        </div>
                                    </div>
                                    <div class="form-group row">
                                        <label
                                            class="text-bold col-4 col-form-label text-right"
                                            for="inputContact8"
                                            >District</label
                                        >
                                        <div class="col-8">
                                            <input
                                                class="form-control"
                                                name="district"
                                                type="text"
                                                :value="reg.ResidentDistrict"
                                            />
                                        </div>
                                    </div>
                                    <div class="form-group row">
                                        <label
                                            class="text-bold col-4 col-form-label text-right"
                                            for="inputContact8"
                                            >Ward</label
                                        >
                                        <div class="col-8">
                                            <input
                                                class="form-control"
                                                name="ward"
                                                type="text"
                                                :value="reg.ResidentWard"
                                            />
                                        </div>
                                    </div>
                                    <div class="form-group row">
                                        <label
                                            class="text-bold col-4 col-form-label text-right"
                                            for="inputContact8"
                                            >Street</label
                                        >
                                        <div class="col-8">
                                            <input
                                                class="form-control"
                                                name="street"
                                                type="text"
                                                :value="reg.ResidentStreet"
                                            />
                                        </div>
                                    </div>
                                    <div class="form-group row">
                                        <label
                                            class="text-bold col-4 col-form-label text-right"
                                            for="inputContact8"
                                        >
                                            Registered on
                                        </label>
                                        <div class="col-8">
                                            <input
                                                class="form-control"
                                                id="inputContact8"
                                                type="text"
                                                :value="reg.CreatedTime"
                                                readonly
                                            />
                                        </div>
                                    </div>

                                    <div class="form-group">
                                        <div class="row">
                                            <div class="col-4">
                                                <a
                                                    class="mb-2 text-info d-flex align-items-center link-unstyled"
                                                    :href="
                                                        'data:application/png;base64,' +
                                                            reg.IDFront
                                                    "
                                                    :download="
                                                        reg.FirstName +
                                                            ' ' +
                                                            reg.Surname +
                                                            '-Passport-front.jpg'
                                                    "
                                                    ><span
                                                        ><em
                                                            class="far fa-file fa-fw mr-2 text-inverse"
                                                        ></em
                                                        ><span
                                                            >Front Passport
                                                            File</span
                                                        ></span
                                                    ></a
                                                >
                                            </div>

                                            <div class="col-8">
                                                <img
                                                    class="img-fluid img-thumbnail"
                                                    :src="
                                                        'data:image/png;base64,' +
                                                            reg.IDFront
                                                    "
                                                    alt="Contact"
                                                />
                                            </div>
                                        </div>
                                    </div>

                                    <div class="form-group">
                                        <div class="row">
                                            <div class="col-4">
                                                <a
                                                    class="mb-2 text-info d-flex align-items-center link-unstyled"
                                                    :href="
                                                        'data:application/png;base64,' +
                                                            reg.IDBack
                                                    "
                                                    :download="
                                                        reg.FirstName +
                                                            ' ' +
                                                            reg.Surname +
                                                            '-Passport-back.jpg'
                                                    "
                                                    ><span
                                                        ><em
                                                            class="far fa-file fa-fw mr-2 text-inverse"
                                                        ></em
                                                        ><span
                                                            >Back Passport
                                                            File</span
                                                        ></span
                                                    ></a
                                                >
                                            </div>

                                            <div class="col-8">
                                                <img
                                                    class="img-fluid img-thumbnail"
                                                    :src="
                                                        'data:image/png;base64,' +
                                                            reg.IDBack
                                                    "
                                                    alt="Contact"
                                                />
                                            </div>
                                        </div>
                                    </div>

                                    <div v-show="showMainButtons" class="row">
                                        <div class="form-group col-4"></div>
                                        <div class="col-4">
                                            <a
                                                class="btn btn-danger btn-lg text-white"
                                                @click="showdeclineForm"
                                            >
                                                <i
                                                    class="far fa-times-circle"
                                                ></i>
                                                Decline</a
                                            >
                                        </div>
                                        <div class="col-4">
                                            <a
                                                class="btn btn-success btn-lg text-white"
                                                style="float: right"
                                                @click="acceptWakala"
                                            >
                                                <i
                                                    class="far fa-check-circle"
                                                ></i>
                                                Accept
                                            </a>
                                        </div>
                                    </div>
                                </form>

                                <!-- Start decline Form -->

                                <div v-show="showDeclineForm" class="card">
                                    <div class="card-body">
                                        <form
                                            class="mb-3"
                                            id="loginForm"
                                            novalidate
                                        >
                                            <!-- <div class="form-group">
                                                <textarea
                                                    name="rejectReason"
                                                    id="form7"
                                                    class="md-textarea form-control"
                                                    rows="3"
                                                    v-model="
                                                        fields.declineReason
                                                    "
                                                ></textarea>
                                                <div
                                                    v-if="
                                                        errors &&
                                                            errors.declineReason
                                                    "
                                                    class="text-danger"
                                                >
                                                    {{
                                                        errors.declineReason[0]
                                                    }}
                                                </div>
                                            </div> -->

                                            <div class="row">
                                                <div class="form-group col-12">
                                                    <label
                                                        class="text-bold"
                                                        for="registrationCategory"
                                                        >Rejection Reason</label
                                                    >

                                                    <select
                                                        class="custom-select"
                                                        id="declineReason"
                                                        name="declineReason"
                                                        v-model="
                                                            fields.declineReason
                                                        "
                                                    >
                                                        <option
                                                            v-for="reason in reasons"
                                                            v-bind:value="
                                                                reason
                                                            "
                                                            v-bind:key="reason"
                                                            >{{
                                                                reason
                                                            }}</option
                                                        >
                                                    </select>

                                                    <div
                                                        v-if="
                                                            errors &&
                                                                errors.declineReason
                                                        "
                                                        class="text-danger"
                                                    >
                                                        {{
                                                            errors
                                                                .declineReason[0]
                                                        }}
                                                    </div>
                                                </div>
                                            </div>

                                            <div class="form-group">
                                                <a
                                                    class="btn btn-info btn-lg text-white"
                                                    @click="cancelDecline"
                                                >
                                                    <i
                                                        class="far fa-check-circle"
                                                    ></i>
                                                    Cancel
                                                </a>

                                                <a
                                                    class="btn btn-success btn-lg text-white"
                                                    style="float: right"
                                                    @click="declineWakala"
                                                >
                                                    <i
                                                        class="far fa-check-circle"
                                                    ></i>
                                                    Confirm
                                                </a>
                                            </div>
                                        </form>
                                    </div>
                                </div>

                                <!-- End decline Form -->
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>

<script>
export default {
    data() {
        return {
            regID: null,
            brela: false,
            regs: null,
            reg: {},
            errors: {},
            fields: {},
            success: false,
            loaded: true,
            loading: true,
            message: null,
            reason: false,
            showDeclineForm: false,
            showMainButtons: true,
            reasons: [
                "Blur portrait image",
                " Invalid portrait image",
                "Portrait mismatch",
                "Unreadable passport image",
                "Invalid Passport image",
                " Passport details mismatch",
                "Invalid signature"
            ]
        };
    },
    created() {
        let loader = this.$loading.show({
            // Optional parameters
            container: this.fullPage ? null : this.$refs.formContainer,
            "is-full-page": true,
            loader: "dots",
            color: "red"
        });

        setTimeout(() => {
            this.regID = sessionStorage.getItem("regID");

            this.fields.RegID = this.regID;

            axios
                .post(
                    "/api/support/visitor-alternative-registrations/single",
                    this.fields
                )
                .then(response => {
                    this.fields = {}; //Clear input fields.
                    this.loaded = true;
                    this.success = true;

                    this.reg = response.data[0];
                })
                .catch(error => {
                    this.loaded = true;

                    if (error.response.status === 422) {
                        this.errors = error.response.data.errors || {};
                    } else if (error.response.status === 400) {
                        this.message = error.response.data.message || {};
                    } else {
                        this.message = "An error has occured !";
                    }
                });

            loader.hide();
        }, 5000);
    },
    methods: {
        declineWakala() {
            if (this.loaded) {
                this.loaded = false;
                this.success = false;
                this.errors = {};
                this.message = null;

                let loader = this.$loading.show({
                    // Optional parameters
                    container: this.fullPage ? null : this.$refs.formContainer,
                    "is-full-page": false,
                    loader: "dots",
                    color: "red"
                });

                this.fields.regID = this.regID;
                this.fields.verificationStatus = 3;
                //this.fields.declineReason = this.regID;

                this.fields.firstName = this.$refs.reDetailsform.firstName.value;
                this.fields.middleName = this.$refs.reDetailsform.middleName.value;
                this.fields.lastName = this.$refs.reDetailsform.lastName.value;

                this.fields.gender = this.$refs.reDetailsform.gender.value;
                this.fields.dob = this.$refs.reDetailsform.dob.value;
                this.fields.nationality = this.$refs.reDetailsform.nationality.value;
                this.fields.idNumber = this.$refs.reDetailsform.idNumber.value;

                this.fields.msisdn = this.$refs.reDetailsform.msisdn.value;
                this.fields.region = this.$refs.reDetailsform.region.value;
                this.fields.district = this.$refs.reDetailsform.district.value;
                this.fields.ward = this.$refs.reDetailsform.ward.value;
                this.fields.street = this.$refs.reDetailsform.street.value;

                axios
                    .post(
                        "/api/support/visitor-alternative-registrations/review",
                        this.fields
                    )
                    .then(response => {
                        loader.hide();
                        this.fields = {}; //Clear input fields.
                        this.loaded = true;
                        this.success = true;

                        Swal.fire({
                            icon: "success",
                            title: "Success",
                            text: "Declined customer registration successful !"
                        }).then(() => {
                            window.location = "/home";
                        });
                    })
                    .catch(error => {
                        this.loaded = true;
                        loader.hide();
                        console.log(error);
                        if (error.response.status === 422) {
                            this.errors = error.response.data.errors || {};
                        } else {
                            this.message = error.response.data.message;
                        }
                    });
            }
        },
        acceptWakala() {
            if (this.loaded) {
                this.loaded = false;
                this.success = false;
                this.errors = {};
                this.message = null;

                let loader = this.$loading.show({
                    // Optional parameters
                    container: this.fullPage ? null : this.$refs.formContainer,
                    "is-full-page": false,
                    loader: "dots",
                    color: "red"
                });

                this.fields.regID = this.regID;
                this.fields.verificationStatus = 1;

                this.fields.firstName = this.$refs.reDetailsform.firstName.value;
                this.fields.middleName = this.$refs.reDetailsform.middleName.value;
                this.fields.lastName = this.$refs.reDetailsform.lastName.value;

                this.fields.gender = this.$refs.reDetailsform.gender.value;
                this.fields.dob = this.$refs.reDetailsform.dob.value;
                this.fields.nationality = this.$refs.reDetailsform.nationality.value;
                this.fields.idNumber = this.$refs.reDetailsform.idNumber.value;

                this.fields.msisdn = this.$refs.reDetailsform.msisdn.value;
                this.fields.region = this.$refs.reDetailsform.region.value;
                this.fields.district = this.$refs.reDetailsform.district.value;
                this.fields.ward = this.$refs.reDetailsform.ward.value;
                this.fields.street = this.$refs.reDetailsform.street.value;

                axios
                    .post(
                        "/api/support/visitor-alternative-registrations/review",
                        this.fields
                    )
                    .then(response => {
                        console.log(response.data);
                        //this.fields = {}; //Clear input fields.
                        this.loaded = true;
                        this.success = true;
                        loader.hide();

                        // Swal.fire({
                        //     icon: "success",
                        //     title: "Success",
                        //     text: "Successful customer registration !"
                        // }).then(() => {
                        //     window.location = "/home";
                        // });
                    })
                    .catch(error => {
                        this.loaded = true;
                        loader.hide();
                        console.log(error);
                        if (error.response.status === 422) {
                            this.errors = error.response.data.errors || {};
                        } else {
                            this.message = error.response.data.message;
                        }
                    });
            }
        },

        showdeclineForm() {
            this.showDeclineForm = true;
            this.showMainButtons = false;
        },
        cancelDecline() {
            this.showDeclineForm = false;
            this.showMainButtons = true;
        }
    },
    beforeDestroy() {
        console.log(
            `At this point, watchers, child components, and event listeners have not been teared down yet.`
        );

        sessionStorage.removeItem("agent");
    }
};
</script>
