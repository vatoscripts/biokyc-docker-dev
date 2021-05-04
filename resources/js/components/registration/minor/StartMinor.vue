<template>
    <div class="row">
        <!-- START dashboard main content-->
        <div class="col-xl-12">
            <div
                v-show="message"
                class="alert alert-danger alert-block mt-1 text-center"
            >
                <button type="button" class="close" data-dismiss="alert">
                    ×
                </button>
                <span class="lead">{{ message }}</span>
            </div>
            <div class="card b">
                <div class="card-body">
                    <form
                        @submit.prevent="submit"
                        class="mb-3"
                        id="registerBulkForm"
                    >
                        <div class="form-group">
                            <div class="input-group with-focus mb-2">
                                <input
                                    name="companyName"
                                    class="form-control"
                                    id="companyName"
                                    type="text"
                                    v-model="fields.msisdn"
                                    placeholder="Enter mobile number e.g 0754000000"
                                />
                                <div class="input-group-append">
                                    <button
                                        id="checkMsisdnIcapBtn"
                                        class="btn btn-block btn-info"
                                        type="submit"
                                    >
                                        <span class="fa fa-search-plus"></span>
                                        Search Msisdn
                                    </button>
                                </div>
                            </div>
                        </div>
                        <div v-if="errors && errors.msisdn" class="text-danger">
                            {{ errors.msisdn[0] }}
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
            items: null,
            showRegisterNew: false
        };
    },
    mounted() {
        this.hasValue = false;
        this.showRegisterNew = false;
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
                    .post("/api/one-sim/minor/check-msisdn", this.fields)
                    .then(res => {
                        console.log(res.data);
                        loader.hide();

                        window.location = "/one-sim/minor/register";

                        this.fields = {}; //Clear input fields.
                        this.loaded = true;
                        this.success = true;
                        this.loading = false;
                    })
                    .catch(error => {
                        this.loaded = true;
                        loader.hide();

                        console.log(error);
                        if (error.response.status === 422) {
                            this.errors = error.response.data.errors || {};
                        } else if (error.response.status === 400) {
                            this.message = error.response.data.message || {};
                        } else {
                            this.message = "An error has occured !";
                        }
                    });
            }
        }
    }
};
</script>
