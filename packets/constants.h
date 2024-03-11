#pragma once
#include <array>

const static unsigned short IPV4 = 0x0800;

using Byte = unsigned char;
using IP = std::array<Byte, 4>;

namespace Packets{
    struct Packet {
        unsigned short type{};
        IP source_ip{};
        IP destination_ip{};
    };
}