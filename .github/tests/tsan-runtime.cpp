// Copyright (c) 2026 The Nito Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <scheduler.h>

#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <future>
#include <mutex>
#include <string_view>
#include <thread>

using namespace std::chrono_literals;

int main(int argc, char** argv)
{
    if (argc == 2 && std::string_view{argv[1]} == "--race") {
        // Negative control: the runtime must still reject unsynchronized writes.
        // Sequence the accesses with relaxed atomics: execution order alone
        // must not establish a happens-before edge for value. A simultaneous
        // start and two short-lived writers can miss the report under TSan.
        int value{0};
        std::atomic<int> phase{0};
        std::thread writer([&] {
            value = 1;
            phase.store(1, std::memory_order_relaxed);
            // Keep the writer alive until the second access, without adding
            // release/acquire synchronization between the conflicting writes.
            while (phase.load(std::memory_order_relaxed) != 2) std::this_thread::yield();
        });
        while (phase.load(std::memory_order_relaxed) != 1) std::this_thread::yield();
        value = 2;
        phase.store(2, std::memory_order_relaxed);
        writer.join();
        std::printf("Undetected race: %d\n", value);
        return 0;
    }
    assert(argc == 1);

    // The second lock cannot succeed until wait_until releases the mutex.
    // This exercises pthread_cond_clockwait on Ubuntu 22.04/libstdc++, whose
    // interceptor is absent from GCC 11's TSan runtime (GCC PR 101978).
    std::mutex mutex;
    std::condition_variable condition;
    std::atomic<bool> waiting{false};
    bool ready{false};
    std::thread waiter([&] {
        std::unique_lock lock{mutex};
        waiting.store(true);
        assert(condition.wait_until(lock, std::chrono::steady_clock::now() + 5s, [&] { return ready; }));
    });
    while (!waiting.load()) std::this_thread::yield();
    {
        std::lock_guard lock{mutex};
        ready = true;
    }
    condition.notify_one();
    waiter.join();

    // Compile and exercise the real scheduler, without Qt or a node/datadir.
    CScheduler scheduler;
    scheduler.scheduleFromNow([] {}, 1h);
    scheduler.m_service_thread = std::thread([&] { scheduler.serviceQueue(); });
    for (int i = 0; i < 20; ++i) {
        std::promise<void> done;
        auto completed = done.get_future();
        std::this_thread::sleep_for(5ms);
        scheduler.scheduleFromNow([&] { done.set_value(); }, 1ms);
        assert(completed.wait_for(5s) == std::future_status::ready);
    }
    scheduler.stop();
    std::puts("PASS: timed condition waits and scheduler rescheduling");
}
