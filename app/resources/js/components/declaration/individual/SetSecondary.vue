<template>
    <div class="row">
        <!-- START dashboard main content-->
        <div class="col-xl-12">
            <div
                v-show="message"
                class="alert alert-warning alert-block mt-1 text-center"
            >
                <span class="lead">{{ message }}</span>
            </div>
            <div class="card b">
                <div class="card-body">
                    <form @submit.prevent="submit" class="mb-3">
                        <div class="form-group">
                            <label class="text-bold">List of msisdn</label>

                            <div class="form-row">
                                <div
                                    class="col-2"
                                    v-for="item in items"
                                    v-bind:value="item.ID"
                                    v-bind:key="item.ID"
                                >
                                    <label class="radio-inline">
                                        <input
                                            type="radio"
                                            class="radio-button mr-2"
                                            :value="item"
                                            name="secondary-msisdn"
                                            v-model="fields.msisdnSecondary"
                                        />
                                        {{ item[0] }}
                                    </label>
                                </div>
                            </div>
                            <div
                                v-if="errors && errors.msisdnSecondary"
                                class="text-danger mb-2"
                            >
                                {{ errors.msisdnSecondary[0] }}
                            </div>
                        </div>

                        <div class="form-row">
                            <div class="form-group col-6">
                                <label
                                    class="font-weight-bold mb-4"
                                    for="blockReason"
                                    >Reason for additional msisdn</label
                                >
                                <select
                                    class="custom-select text-center"
                                    id="tcraReason"
                                    name="tcraReason"
                                    @change="onReasonChange($event)"
                                >
                                    <option class value
                                        >--------------Choose reason
                                        ------------</option
                                    >
                                    <option value="1000"
                                        >For additional devices (phones,
                                        tablets, CCTV, routers etc)</option
                                    >
                                    <option value="1001"
                                        >To separate office and private
                                        usage</option
                                    >
                                    <option value="1002"
                                        >To separate business and personal
                                        usage</option
                                    >
                                    <option value="1003"
                                        >For mobile financial services</option
                                    >
                                    <option value="1004"
                                        >Mobile number porting - with
                                        reasons</option
                                    >
                                    <option value="1005"
                                        >Increase branches/shops or
                                        business</option
                                    >
                                </select>
                                <div
                                    v-if="errors && errors.tcraReason"
                                    class="text-danger"
                                >
                                    {{ errors.tcraReason[0] }}
                                </div>
                            </div>
                        </div>

                        <div class="form-group col-4">
                            <button
                                id="filterRegJourneyDates"
                                type="submit"
                                class="btn btn-lg btn-block btn-outline-danger myLead text-bold mt-4"
                            >
                                Set secondary
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        <!-- END dashboard main content-->
    </div>
</template>
<script>
export default {
    data() {
        return {
            fields: {},
            errors: {},
            success: false,
            loaded: true,
            loading: false,
            message: null,
            checked: false,
            hasValue: false,
            items: null
        };
    },
    mounted() {
        axios
            .get("/api/secondary/get-msisdn")
            .then(response => {
                this.items = response.data;
            })
            .catch(error => {
                Swal.fire({
                    icon: "error",
                    title: "Error",
                    text: "Something went wrong while fetching results !"
                }).then(function() {
                    window.location = "/home";
                });
            });
    },
    methods: {
        submit() {
            let loader = this.$loading.show({
                // Optional parameters
                container: this.fullPage ? null : this.$refs.formContainer,
                "is-full-page": true,
                loader: "dots",
                color: "red"
            });

            if (this.loaded) {
                this.loaded = false;
                this.success = false;
                this.errors = {};
                this.message = null;
                this.hasValue = false;
                this.showRegisterNew = false;

                axios
                    .post("/api/secondary/set-msisdn", this.fields)
                    .then(res => {
                        loader.hide();

                        Swal.fire({
                            icon: "success",
                            title: "Success",
                            text: res.data.message
                        }).then(function() {
                            setTimeout(() => {
                                window.location = "/home";
                            }, 3000);
                        });

                        this.fields = {}; //Clear input fields.
                        this.loaded = true;
                        // this.success = true;
                        this.loading = false;
                    })
                    .catch(error => {
                        this.loaded = true;
                        loader.hide();

                        if (error.response.status === 422) {
                            this.errors = error.response.data.errors || {};
                        } else if (error.response.status === 400) {
                            this.message = error.response.data.message || {};
                        } else {
                            this.message = "An error has occured !";
                        }
                    });
            }
        },
        onReasonChange(e) {
            this.fields.tcraReason = e.target.value;
        }
    }
};
</script>
