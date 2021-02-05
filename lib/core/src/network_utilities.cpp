#include "network_utilities.hpp"

#include "irods_get_full_path_for_config_file.hpp"
#include "rodsErrorTable.h"
#include "rodsLog.h"

#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/containers/map.hpp>
#include <boost/interprocess/containers/string.hpp>
#include <boost/interprocess/allocators/allocator.hpp>
#include <boost/interprocess/sync/named_mutex.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>

#include <fmt/format.h>
#include <json.hpp>

#include <fstream>
#include <iterator>
#include <algorithm>
#include <chrono>
#include <memory>

#include <unistd.h>

namespace
{
    namespace bi = boost::interprocess;

    using json = nlohmann::json;

    class hostname_cache
    {
    public:
        struct alias
        {
            alias(const std::string_view _hostname, std::int64_t _expiration)
                : hostname{}
                , expiration{_expiration}
            {
                std::strncpy(hostname, _hostname.data(), _hostname.size());
            }

            char hostname[256];         // FQDN are 253 characters long.
            std::int64_t expiration;   // Seconds since epoch.
        }; // struct alias

        // clang-format off
        using segment_manager_type = bi::managed_shared_memory::segment_manager;
        using void_allocator_type  = bi::allocator<void, segment_manager_type>;
        using char_allocator_type  = bi::allocator<char, segment_manager_type>;
        using key_type             = bi::basic_string<char, std::char_traits<char>, char_allocator_type>;
        using mapped_type          = alias;
        using value_type           = std::pair<const key_type, mapped_type>;
        using value_allocator_type = bi::allocator<value_type, segment_manager_type>;
        using map_type             = bi::map<key_type, mapped_type, std::less<key_type>, value_allocator_type>;
        using clock_type           = std::chrono::system_clock;
        // clang-format on
        
        hostname_cache() = default;

        hostname_cache(const hostname_cache&) = delete;
        auto operator=(const hostname_cache&) -> hostname_cache& = delete;

        static auto init() -> void
        {
            owner_pid_ = getpid();
            segment_ = std::make_unique<bi::managed_shared_memory>(bi::open_or_create, segment_name_, 1'000'000);
            allocator_ = std::make_unique<void_allocator_type>(segment_->get_segment_manager());
            mutex_ = std::make_unique<bi::named_mutex>(bi::open_or_create, mutex_name_);
            map_ = segment_->construct<map_type>(map_name_)(std::less<key_type>{}, *allocator_);
            read_hosts_config_file();
        }

        static auto deinit() noexcept -> void
        {
            if (getpid() != owner_pid_) {
                return;
            }

            try {
                // clang-format off
                if (map_)       { map_ = nullptr; }
                if (mutex_)     { mutex_.reset(); }
                if (allocator_) { allocator_.reset(); }
                if (segment_)   { segment_.reset(); }
                // clang-format on

                bi::named_mutex::remove(mutex_name_);
                bi::shared_memory_object::remove(segment_name_);
            }
            catch (...) {}
        }

        auto hosts_config() const noexcept -> json&
        {
            return hosts_config_;
        }

        auto insert_or_assign(const std::string_view _hostname, const std::string_view _long_hostname) -> void
        {
            rodsLog(LOG_NOTICE, "%s :: _hostname=%s, _long_hostname=%s", __func__, _hostname.data(), _long_hostname.data());
            bi::scoped_lock lk{*mutex_};
            key_type key{_hostname.data(), *allocator_};
            using namespace std::chrono_literals;
            const auto expiration = clock_type::now() + 60s;
            // FIXME This can fail because the long hostname can exceed the size of the buffer in
            // the alias instance.
            map_->insert_or_assign(key, mapped_type{_long_hostname, expiration.time_since_epoch().count()});
        }

        auto lookup(const std::string_view& _hostname) -> std::optional<std::string>
        {
            rodsLog(LOG_NOTICE, "%s :: _hostname=%s", __func__, _hostname.data());
            bi::scoped_lock lk{*mutex_};

            key_type key{_hostname.data(), *allocator_};

            if (auto iter = map_->find(key); iter != map_->end()) {
                // If the entry has not expired, then bump the expiration timestamp and
                // return the entry's hostname alias.
                if (auto& v = iter->second; v.expiration > clock_type::now().time_since_epoch().count()) {
                    using namespace std::chrono_literals;
                    v.expiration = (clock_type::now() + 60s).time_since_epoch().count();
                    return v.hostname;
                }

                // Remove the expired entry.
                map_->erase(iter);
            }
#if 0
            // Remove expired entries.
            const auto is_expired = [now = clock_type::now().time_since_epoch().count()](const value_type& _v) {
                return now > _v.second.expiration;
            };

            std::erase(std::remove_if(map_->begin(), end, is_expired), end);
#endif
            return std::nullopt;
        }

    private:
        static auto read_hosts_config_file() -> void
        {
            try {
                std::string config_path;

                // Find the hosts_config.json file if it exists.
                if (const auto error = irods::get_full_path_for_config_file("hosts_config.json", config_path); !error.ok()) {
                    // TODO Handle error.
                    return;
                }

                std::ifstream in{config_path};

                if (!in) {
                    // TODO Handle error.
                    THROW(SYS_CONFIG_FILE_ERR, fmt::format("Could not open hosts_config.json for reading [path={}]", config_path));
                    return;
                }

                in >> hosts_config_;
            }
            catch (const json::exception& e) {
                // TODO Handle error.
                THROW(SYS_CONFIG_FILE_ERR, e.what());
            }
        }

        // clang-format off
        inline static const char* const segment_name_ = "irods_hostname_cache";
        inline static const char* const mutex_name_   = "irods_hostname_cache_mutex";
        inline static const char* const map_name_     = "irods_hostname_cache_map";
        // clang-format on

        inline static std::unique_ptr<bi::managed_shared_memory> segment_;
        inline static std::unique_ptr<void_allocator_type> allocator_;
        inline static std::unique_ptr<bi::named_mutex> mutex_;
        inline static map_type* map_;
        inline static pid_t owner_pid_;
        inline static json hosts_config_;
    }; // class hostname_cache

    // The private hostname_cache instance shared by all hostname_cache-related functions.
    hostname_cache hostname_cache;
} // anonymous namespace

namespace irods
{
    auto init_hostname_cache() -> void
    {
        hostname_cache::init();
    }

    auto deinit_hostname_cache() -> void
    {
        hostname_cache::deinit();
    }

    auto get_hostname_from_cache(const std::string_view _hostname, const std::string_view _hosts_config)
        -> std::optional<std::string>
    {
        rodsLog(LOG_NOTICE, "%s :: _hostname=%s", __func__, _hostname.data());

        // Return the cached hostname for the target server.
        if (const auto alias = hostname_cache.lookup(_hostname); alias) {
            const auto msg = fmt::format("Returning hostname alias from cache [hostname={}, alias={}].", _hostname, *alias);
            rodsLog(LOG_NOTICE, msg.data());
            return *alias;
        }

        rodsLog(LOG_NOTICE, fmt::format("Hostname not in cache [hostname={}].", _hostname).data());

        try {
            const auto&& hosts_config = [_hosts_config] {
                return _hosts_config.empty() ? hostname_cache.hosts_config() : json::parse(_hosts_config);
            }();

            const auto& host_entries = hosts_config.at("host_entries");
            const auto end = std::end(host_entries);

            // Find the entry that contains _hostname.
            // This entry will contain the list of hostname aliases.
            const auto iter = std::find_if(std::begin(host_entries), end, [_hostname](const json& _entry) {
                const std::string_view address_type = (_hostname == "localhost") ? "local" : "remote";

                if (address_type == _entry.at("address_type").get<std::string>()) {
                    if (_hostname == "localhost") {
                        return true;
                    }

                    const auto& addresses = _entry.at("addresses");
                    const auto end = std::end(addresses);

                    return end != std::find_if(std::begin(addresses), end, [_hostname](const json& _address) {
                        return _address.at("address").get<std::string>() == _hostname;
                    });
                }

                return false;
            });

            if (iter == end) {
                const auto msg = fmt::format("No hostname alias defined in hosts_config.json [hostname={}].", _hostname);
                rodsLog(LOG_NOTICE, msg.data());
                return std::nullopt;
            }

            std::string alias;

            for (auto&& address : iter->at("addresses")) {
                if (auto tmp = address.at("address").get<std::string>(); tmp.size() > alias.size()) {
                    alias = std::move(tmp);
                }
            }

            hostname_cache.insert_or_assign(_hostname, alias);

            return alias;
        }
        catch (const irods::exception& e) {
            rodsLog(LOG_ERROR, e.what());
        }
        catch (const std::exception& e) {
            rodsLog(LOG_ERROR, e.what());
        }

        return std::nullopt;
    }
} // namespace irods

