#include "reader.h"
#include <stdexcept>

namespace Packets {

    std::optional<Packet> Reader::ReadPacket() {
        if (!file_) {
            return std::nullopt;
        }

        unsigned short len;
        file_.read(reinterpret_cast<char *>(&len), 2);

        // Skipping dest and src mac
        file_.seekg(12, std::ios::cur);
        len -= 12;

        // Reading type
        unsigned char buff[2];
        file_.read(reinterpret_cast<char *>(buff), 2);
        unsigned short type = buff[0];
        type <<= 8;
        type |= buff[1];
        len -= 2;

        if (type != IPV4) {
            file_.seekg(len, std::ios::cur);
            return Packet{type};
        }

        // Skipping IPv4 header without sip, dip, options and data
        file_.seekg(12, std::ios::cur);
        len -= 12;

        Packet packet{type};
        file_.read(reinterpret_cast<char *>(packet.source_ip.data()), 4);
        file_.read(reinterpret_cast<char *>(packet.destination_ip.data()), 4);
        len -= 8;

        file_.seekg(len, std::ios::cur);

        return packet;
    }

    Reader::Reader(std::string_view filename)
            : file_(filename, std::ios::in | std::ios::binary) {
        if (!file_) {
            throw std::invalid_argument("cannot open file");
        }
    }
} // Packets