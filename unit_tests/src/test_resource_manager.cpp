#include <catch2/catch.hpp>

#include "irods/irods_configuration_keywords.hpp"
#include "irods/irods_load_plugin.hpp"
#include "irods/irods_resource_manager.hpp"
#include "irods/irods_at_scope_exit.hpp"
#include "irods/irods_resource_types.hpp"

#include <string>
#include <vector>

TEST_CASE("resource_manager")
{
    //irods::resource_manager mgr;

    const char* type = "unixfilesystem";
    const char* name = "demoResc";
    //const char* ctx  = "";
    std::string ctx;

    //irods::resource_ptr p;
    irods::resource* q{};
    //REQUIRE(irods::load_plugin<irods::resource>(q, type, irods::KW_CFG_PLUGIN_TYPE_RESOURCE, name, "").code() == 0);
    REQUIRE(irods::load_plugin<irods::resource>(q, type, irods::KW_CFG_PLUGIN_TYPE_RESOURCE, name, ctx).code() == 0);
    delete q;
    q = nullptr;
    //p.reset(q);
}
