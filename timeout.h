#ifndef TIMEOUT_H
#define TIMEOUT_H
#include "stdafx.h"

class timeout
{
private:
    time_t syn_sent;
    bool syn_check;
    bool check;
public:
    timeout();
    bool operator<(const timeout& other) const;
    bool checkTimeout(time_t current);
    void setCheck(bool check);
    bool getCheck();
    void setSynCheck(bool check);
    bool getSynCheck();
    void setData(bool check, time_t syn_sent);
};

#endif // TIMEOUT_H
