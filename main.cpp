#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>

#include "bitreader.h"
#include "ts.h"

using namespace std;
// Main method


int main(int argc, char *argv[])
{
    char filename[] = "/home/vcloud/resources/av/demo.ts";

    TSParser ts;
    uint8_t buffer[TS_PACKET_LENGTH];
    BitReader reader;
    TSPacket packet;
    FILE* fp_in = fopen(filename,"rb");
    while(!feof(fp_in)){
        int len = fread(buffer,1,TS_PACKET_LENGTH,fp_in);
        if(len < TS_PACKET_LENGTH){
            break;
        }
        bitreader_init(&reader,buffer,TS_PACKET_LENGTH);
        ParsePacket(&ts,&reader,&packet);
    }
}
