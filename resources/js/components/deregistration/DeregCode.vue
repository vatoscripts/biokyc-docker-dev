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
                        <div class="align-center">
                            <div class="form-row">
                                <div class="form-group col-2">
                                    <label class="text-bold">Code</label>
                                    <input
                                        id="idNumber"
                                        name="idNumber"
                                        class="form-control"
                                        type="text"
                                        placeholder="Enter code number"
                                        v-model="fields.codeNumber"
                                    />
                                    <div
                                        v-if="errors && errors.codeNumber"
                                        class="text-danger"
                                    >
                                        {{ errors.codeNumber[0] }}
                                    </div>
                                </div>

                                <div class="form-group col-6">
                                    <label class="text-bold"
                                        >Reason for de-registering</label
                                    >
                                    <select
                                        class="custom-select"
                                        name="deregReason"
                                        @change="onReasonChange($event)"
                                    >
                                        <option value>SELECT ONE</option>

                                        <option
                                            v-for="reason in reasons"
                                            v-bind:value="reason.code"
                                            v-bind:key="reason.code"
                                            >{{ reason.name }}</option
                                        >
                                    </select>
                                    <div
                                        v-if="errors && errors.deregReason"
                                        class="text-danger"
                                    >
                                        {{ errors.deregReason[0] }}
                                    </div>
                                </div>

                                <div class="form-group col-4">
                                    <button
                                        type="submit"
                                        class="btn btn-lg btn-block btn-outline-danger myLead text-bold mt-4"
                                    >
                                        Submit
                                    </button>
                                </div>
                            </div>
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
            reasons: [
                {
                    code: "I do not know the MSISDN",
                    name: "I do not know the MSISDN"
                },
                {
                    code: "Inactive MISSDN",
                    name: "Inactive MISSDN"
                },
                {
                    code: "I do not want this MSISDN",
                    name: "I do not want this MSISDN"
                },
                { code: "Change ownership", name: "Change ownership" }
            ]
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
                    .post("/api/dereg/code", this.fields)
                    .then(res => {
                        loader.hide();

                        // this.fields = {}; //Clear input fields.
                        this.loaded = true;
                        // this.success = true;
                        this.loading = false;

                        Swal.fire({
                            icon: "success",
                            title: "Success",
                            text: res.data.message
                        }).then(function() {
                            window.location = "/home";
                        });
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
            this.fields.deregReason = e.target.value;
        }
    }
};
</script>
