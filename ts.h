#ifndef TS_H
#define TS_H

#include <stdio.h>
#include <stdint.h>
#include <memory.h>
#include <stdlib.h>
#include <string.h>
#include <deque>
#include <string>
using namespace std;
#include "bitreader.h"

enum TSEnum{
    TS_PACKET_LENGTH  =188,
    TS_STREAM_VIDEO	 = 0x1b,
    TS_STREAM_AUDIO = 0x0f,
    TS_SYNC_CODE = 0x47,
};

struct TS;
struct TSStream;
struct TSProgram;

struct TSPacket{
    uint32_t sync_byte;
    uint32_t transport_error_indicator;
    uint32_t payload_unit_start_indicator;
    uint32_t transport_priority;
    uint32_t pid;
    uint32_t transport_scrambling_control;
    uint32_t adaptation_field_control;
    uint32_t continuity_counter;

};

struct PATLoopInfo{
    uint32_t program_number;
    uint32_t reserved;
    uint32_t pid;// network_pid or program_map_pid
};

struct PAT{ // Program Association Table
    uint32_t table_id;
    uint32_t section_syntax_indicator;
    uint32_t zero_byte;
    uint32_t reserved;
    uint32_t section_length;
    uint32_t transport_stream_id;
    uint32_t reserved2;
    uint32_t version_number;
    uint32_t current_next_indicator;
    uint32_t section_number;
    uint32_t last_section_number;
    deque<PATLoopInfo*> nloops;
    uint32_t crc;
};

struct PMTLoopInfo{
    uint32_t stream_type;
    uint32_t reserved;
    uint32_t elementary_pid;
    uint32_t reserved2;
    uint32_t es_info_lenght;
};

struct PMT{ // program map table
    uint32_t table_id;
    uint32_t section_syntax_indicator;
    uint32_t zero_byte;
    uint32_t reserved;
    uint32_t section_length;
    uint32_t program_number;
    uint32_t reserved2;
    uint32_t version_number;
    uint32_t current_next_indicator;
    uint32_t section_number;
    uint32_t last_section_number;
    uint32_t reserved3;
    uint32_t PCR_PID;
    uint32_t reserved4;
    uint32_t program_info_length;
    string descriptors;// skip
    deque<PMTLoopInfo*> nloops;
    uint32_t crc;
};

struct TSProgram{
    uint32_t program_map_pid;
    uint64_t first_pts;
    int first_pts_valid;
    deque<TSStream*> streams;
};

struct TSStream{
    TSProgram* program;
    uint32_t stream_type;

    uint32_t pid;
    uint32_t payload_started;
    char buffer[128 * 1024];
    size_t buffer_size;
};

struct TS{
    PAT pat;
    PMT pmt;
    deque<TSProgram*> programs;
};

bool ParsePacket(TS* ts,BitReader* reader);
bool ParseAdaptionField(TS* ts,BitReader* reader);
bool ParsePayload(TS* ts,BitReader* reader,uint32_t pid, uint32_t payload_unit_start_indicator);
bool ParsePAT(TS* ts, BitReader* reader);//ProgramAssociationTable
bool ParseProgramMap(TS* ts, TSProgram *program, BitReader* reader);
bool ParseStream(TSStream *stream, uint32_t payload_unit_start_indicator, BitReader* reader);
bool ParsePES(TSStream *stream, BitReader* reader);
int64_t ParseTSTimestamp(BitReader* reader);

void AddProgram(TS *ts, uint32_t programMapPID);
void AddStream(TSProgram *program, uint32_t elementaryPID, uint32_t streamType);

TSStream *GetStreamByPID(TSProgram *program, uint32_t pid);
TSProgram *GetProgramByPID(TS *ts, uint32_t pid);

void FlushStreamData(TSStream *stream);
void OnPayloadData(TSStream *stream, uint32_t PTS_DTS_flag, uint64_t PTS, uint64_t DTS, uint8_t *data, size_t size);











#endif // TS_H
