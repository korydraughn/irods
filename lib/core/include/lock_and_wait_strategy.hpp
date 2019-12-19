#ifndef IRODS_LOCK_AND_WAIT_STRATEGY_HPP
#define IRODS_LOCK_AND_WAIT_STRATEGY_HPP

#include <functional>
#include <condition_variable>

namespace irods::experimental
{
    class lock_and_wait_strategy
    {
    public:
        // clang-format off
        using wait_predicate = std::function<bool()>;
        using the_work       = std::function<void()>;
        // clang-format on

        virtual ~lock_and_wait_strategy() {};

        virtual void operator()(wait_predicate, the_work) = 0; 
    };

    class do_not_lock_and_wait
        : public lock_and_wait_strategy
    {
    public:
        void operator()(wait_predicate, the_work w) override
        {
            w();
        }
    }; 

    class lock_and_wait
        : public lock_and_wait_strategy
    {
    public:
        void operator()(wait_predicate p, the_work w) override
        {
            {
                std::unique_lock<std::mutex> lk{mtx_};
                cv_.wait(lk, p);
                w();
            }

            cv_.notify_all();
        }

    private:
        std::condition_variable cv_;
        std::mutex mtx_;
    }; 
} // namespace irods::experimental

#endif   // IRODS_LOCK_AND_WAIT_STRATEGY_HPP
