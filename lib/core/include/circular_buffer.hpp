#ifndef IRODS_CIRCULAR_BUFFER_HPP
#define IRODS_CIRCULAR_BUFFER_HPP

#include "lock_and_wait_strategy.hpp"

#include <boost/circular_buffer.hpp>

namespace irods::experimental
{
    template <typename T>
    class circular_buffer
    {
    public:
        // clang-format off
        using lock_and_wait_pointer = std::unique_ptr<lock_and_wait_strategy>;
        using size_type             = typename boost::circular_buffer<T>::size_type;
        // clang-format on

        circular_buffer(std::size_t capacity,
                        lock_and_wait_pointer lws = std::make_unique<lock_and_wait>())
            : cb_{capacity}
            , lws_{std::move(lws)}
        {
        }

        size_type size()
        {
            size_type result = 0;

            (*lws_)([] { return true; },
                    [this, &result] { result = cb_.size(); });

            return result;
        }

        bool empty()
        {
            bool result = true;

            (*lws_)([] { return true; },
                    [this, &result] { result = cb_.empty(); });

            return result;
        }

        T& front()
        {
            T* p = nullptr;

            (*lws_)([] { return true; },
                    [this, &p] { p = &*cb_.begin(); });

            return *p;
        }

        void pop_front(T& entry)
        {
            (*lws_)([this] { return 0 < cb_.size(); },
                    [this, &entry] {
                        auto iter = cb_.begin();
                        entry = *iter;
                        cb_.pop_front();
                    });
        }

        void push_back(const T& entry)
        {
            (*lws_)([this] { return cb_.size() < cb_.capacity(); },
                    [this, &entry] { cb_.push_back(entry); });
        }

        void clear()
        {
            (*lws_)([] { return true; },
                    [this] { cb_.clear(); });
        }

    private:
        boost::circular_buffer<T> cb_;
        std::unique_ptr<lock_and_wait_strategy> lws_;
    }; // class circular_buffer
} // namespace irods::experimental 

#endif // IRODS_CIRCULAR_BUFFER_HPP

