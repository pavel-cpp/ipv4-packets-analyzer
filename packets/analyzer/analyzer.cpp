#include "analyzer.h"

namespace Packets {
    void Analyzer::AddPacket(const Packet &packet) noexcept {
        ++packets_cnt_;
        if (packet.type == IPV4) {
            ++ipv4_packets_cnt_;
            ++source_to_dest_cnt_[std::make_pair<>(packet.source_ip, packet.destination_ip)];
        }
    }

    Analyzer::Statistics Analyzer::GetStatistics() const noexcept {
        return {packets_cnt_,
                ipv4_packets_cnt_,
                packets_cnt_ - ipv4_packets_cnt_,
                source_to_dest_cnt_
        };
    }
} // Packets