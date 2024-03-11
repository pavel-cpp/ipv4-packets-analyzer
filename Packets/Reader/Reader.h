#pragma once

#include "../constants.h"

#include <fstream>


namespace Packets {

    class Reader {
    public:
        Reader(std::string_view filename);

        std::optional<Packet> ReadPacket();

    private:

        std::fstream file_;
    };

} // Packets

