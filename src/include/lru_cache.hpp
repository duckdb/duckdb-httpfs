#pragma once
#include <list>
#include <unordered_map>
#include "duckdb/common/mutex.hpp"

namespace duckdb {
    template<typename key_t, typename value_t>
    class LRUCache
    {
    public:
        typedef typename std::pair<key_t, value_t> key_value_pair_t;
        typedef typename std::list<key_value_pair_t>::iterator list_iterator_t;
        LRUCache (size_t capacity): _capacity(capacity) {}
        void Put(const key_t& key, const value_t& value) {
            lock_guard<mutex> parallel_lock(lock);
            auto it = _cache_items_map.find(key);
            _cache_items_list.push_front(key_value_pair_t(key, value));
            if (it != _cache_items_map.end()) {
                _cache_items_list.erase(it->second);
                _cache_items_map.erase(it);
            }
            _cache_items_map[key] = _cache_items_list.begin();

            if (_cache_items_map.size() > _capacity) {
                auto last = _cache_items_list.end();
                last--;
                _cache_items_map.erase(last->first);
                _cache_items_list.pop_back();
            }
        }
        bool Get(const key_t& key, value_t& value) {
            lock_guard<mutex> parallel_lock(lock);
            auto it = _cache_items_map.find(key);
            if (it == _cache_items_map.end()) {
                return false;
            } else {
                _cache_items_list.splice(_cache_items_list.begin(), _cache_items_list, it->second);
                value = it->second->second;
                return true;
            }
        }
        void Delete(const key_t& key) {
            lock_guard<mutex> parallel_lock(lock);
            auto it = _cache_items_map.find(key);
            if (it == _cache_items_map.end()) {
                return; //another thread already cleaned up
            }
            _cache_items_list.erase(it->second);
            _cache_items_map.erase(it);
        }
        size_t Size() const {
            return _cache_items_map.size();
        }

    private:
        std::list<key_value_pair_t> _cache_items_list;
        std::unordered_map<key_t, list_iterator_t> _cache_items_map;
        size_t _capacity;
        mutex lock;
    };

}
