#include <iostream>

#include "packets/analyzer/analyzer.h"
#include "packets/reader/reader.h"

using namespace std;

ostream &operator<<(ostream &os, const IP& ip){
    bool is_first = true;
    for(unsigned short number: ip){
        if(is_first){
            os << number;
            is_first = false;
            continue;
        }
        os << '.' << number;
    }
    return os;
}

ostream &operator<<(ostream &os, Packets::Analyzer::Statistics stats) {
    os << "\t\tPackets processed:\t\t" << stats.packets_processed << endl
       << "\tPackets contains IPv4:\t\t" << stats.ipv4_packets << endl
       << "\tPackets without IPv4:\t\t" << stats.no_ipv4_packets << endl << endl;
    for (const auto &[src_dst, cnt]: stats.source_to_dest) {
        os << '\t' << src_dst.first << " -> "s << src_dst.second << "\t\t\t" << cnt << endl;
    }
    return os;
}

void Analyze(Packets::Reader& reader){
    Packets::Analyzer analyzer;

    std::optional<Packets::Packet> packet = reader.ReadPacket();
    while (packet) {
        analyzer.AddPacket(*packet);
        packet = reader.ReadPacket();
    }

    cout << analyzer.GetStatistics() << endl;
}

int main(int argc, char *argv[]) {
    string file_path = "packets.sig";
    if(argc > 2){
        cerr << "To many arguments!" << endl;
        cerr << "\tUse ./packets (path)" << endl;
    }
    if(argc > 1){
        file_path = argv[1];
    }

    try {
        Packets::Reader reader(file_path);
        Analyze(reader);
    }catch(std::invalid_argument&) {
        cerr << "Invalid path or file not found" << endl;
        return 1;
    }
    return 0;
}