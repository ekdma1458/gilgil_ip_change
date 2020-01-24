#include "timeout.h"

timeout::timeout()
{
    this->syn_sent = time(NULL);
    this->syn_check = true;
    this->check = false;
}
bool timeout::operator<(const timeout& other) const{
    return memcmp(this, &other, sizeof(timeout)) < 0;
}
bool timeout::checkTimeout(time_t current){
    if (current - this->syn_sent > 30 && syn_check == true) return true;
    if (current - this->syn_sent > 30 && syn_check == false) {
        this->syn_sent = current;
        this->syn_check = true;
    }
    return false;
}
void timeout::setCheck(bool check){
    this->check = check;
}
bool timeout::getCheck(){
    return this->check;
}
void timeout::setSynCheck(bool check){
    this->syn_check = check;
}
bool timeout::getSynCheck(){
    return this->syn_check;
}
void timeout::setData(bool check, time_t syn_sent){
    this->check = check;
    this->syn_sent = syn_sent;
}
