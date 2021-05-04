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
                            <div
                                v-if="errors && errors.deregMsisdn"
                                class="text-danger mb-2"
                            >
                                {{ errors.deregMsisdn[0] }}
                            </div>
                            <div class="form-row">
                                <div
                                    class="col-2"
                                    v-for="item in items"
                                    v-bind:value="item"
                                    v-bind:key="item"
                                >
                                    <label class="radio-inline">
                                        <input
                                            type="radio"
                                            class="radio-button"
                                            :value="item"
                                            name="dereg-msisdn"
                                            v-model="fields.deregMsisdn"
                                        />
                                        {{ item }}
                                    </label>
                                </div>
                            </div>
                        </div>

                        <div class="form-group col-md-4 col-xs-12">
                            <button
                                type="submit"
                                class="btn btn-lg btn-block btn-outline-danger myLead text-bold mt-4"
                            >
                                Continue
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
    created() {
        axios
            .get("/api/dereg/get-msisdn")
            .then(response => {
                this.items = response.data;
            })
            .catch(error => {
                console.log(error);
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
                    .post("/api/dereg/msisdn", this.fields)
                    .then(res => {
                        loader.hide();
                        // this.fields = {}; //Clear input fields.
                        this.loaded = true;
                        // this.success = true;
                        this.loading = false;

                        window.location = "/de-registration/code";
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
        }
    }
};
</script>
