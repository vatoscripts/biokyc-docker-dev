<template>
    <div class="vld-parent" ref="formContainer">
        <div class="clearfix"></div>
        <div
            v-show="message"
            class="alert alert-warning alert-block text-center"
        >
            <span class="lead">{{ message }}</span>
        </div>
        <div class="table-responsive" v-show="!message">
            <vue-table-dynamic :params="params" ref="table">
                <template v-slot:column-5="{ props }">
                    <span>
                        <a
                            v-on:click="doSomethingCool(props.cellData)"
                            ref="RegID"
                            :id="props.cellData"
                            href="#"
                            ><span>Review</span></a
                        >
                    </span>
                </template>
            </vue-table-dynamic>
        </div>
    </div>
</template>

<script>
import VueTableDynamic from "vue-table-dynamic";

export default {
    data() {
        return {
            wakalas: "",
            message: "",
            fields: {},
            agents: null,
            params: {
                data: [
                    [
                        "Full Name",
                        "Passport No.",
                        "Nationality",
                        "Registration Date",
                        "Msisdn",
                        "Action"
                    ]
                ],
                header: "row",
                border: true,
                stripe: true,
                pagination: true,
                pageSize: 25,
                sort: [0, 1, 2, 3, 4]
                // pageSizes: [5, 10, 20, 50]
            }
        };
    },
    mounted() {
        let loader = this.$loading.show({
            // Optional parameters
            container: this.fullPage ? null : this.$refs.formContainer,
            "is-full-page": true,
            loader: "dots",
            color: "red"
        });

        setTimeout(() => {
            axios
                .get("/api/support/visitor-alternative-registrations")
                .then(response => {
                    let items = response.data;

                    if (items.length > 0) {
                        items.forEach(el => {
                            this.params.data.push([
                                el.FirstName + " " + el.Surname,
                                el.IDNumber,
                                el.Nationality,
                                el.CreatedTime,
                                el.MSISDN,
                                el.RegID
                            ]);
                        });
                    } else {
                        this.message = "No avaliable wakala to verify !";
                    }

                    loader.hide();
                })
                .catch(error => {
                    loader.hide();
                    Toast.fire({
                        icon: "error",
                        title: "An error occured while fetching wakala "
                    });
                });
        }, 2000);
    },
    methods: {
        doSomethingCool(e) {
            this.fields.RegID = e;

            sessionStorage.setItem("regID", e);

            window.location = "/support/alternative-visitors/review";

            return;
        }
    },
    components: { VueTableDynamic }
};
</script>
