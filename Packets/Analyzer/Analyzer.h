#pragma once

#include "../constants.h"

#include <cstdint>
#include <unordered_map>

namespace Packets {

    class IPHasher {
    public:
        uint64_t operator()(const IP &ip) const {
            uint64_t res = 0;
            for (const Byte &b: ip) {
                res |= b;
                res <<= 8;
            }
            return res;
        }
    };

    class PairIPHasher {
    private:
        IPHasher hasher;
    public:
        uint64_t operator()(std::pair<IP, IP> ip_pair) const {
            return hasher(ip_pair.first) + hasher(ip_pair.second);
        }
    };

    class Analyzer {
    public:

        struct Statistics {
            uint64_t packets_processed;
            uint64_t ipv4_packets;
            uint64_t no_ipv4_packets;
            std::unordered_map<
                    std::pair<IP, IP>,
                    int,
                    PairIPHasher
            > source_to_dest;
        };

        void AddPacket(const Packet &packet) noexcept;

        Statistics GetStatistics() const noexcept;

    private:

        std::unordered_map<
                std::pair<IP, IP>,
                int,
                PairIPHasher
        > source_to_dest_cnt_;

        uint64_t packets_cnt_{};
        uint64_t ipv4_packets_cnt_{};
    };

} // Packets
