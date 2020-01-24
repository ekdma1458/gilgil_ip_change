#ifndef FLOWPORT_H
#define FLOWPORT_H
#include "stdafx.h"

class flowport
{
private:
    uint16_t sport;
    uint16_t dport;
public:
    flowport(uint16_t, uint16_t);
    bool operator<(const flowport& other) const;
};

#endif // FLOWPORT_H
