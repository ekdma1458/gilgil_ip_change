#include "flowport.h"
flowport::flowport(uint16_t sport, uint16_t dport)
{
    this->sport=sport;
    this->dport=dport;
}
bool flowport::operator<(const flowport& other) const {
    return memcmp(this, &other, sizeof(flowport)) < 0;
}
