#include "ts.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>


#define ELEMENTS 10



#define LOG(format,...) printf(format,__VA_ARGS__)

bool ParseAdaptionField(TS* ts,BitReader* reader){
    uint32_t adaptation_field_length = get_bits(reader, 8);
    if (adaptation_field_length > 0)
    {
        skip_bits(reader, adaptation_field_length * 8);
    }
}

bool ParsePAT(TS* ts, BitReader* reader){
    size_t i;

    ts->pat.table_id = get_bits(reader, 8);
    LOG("  table_id = %u\n", ts->pat.table_id);

    ts->pat.section_syntax_indicator = get_bits(reader, 1);
    LOG("  section_syntax_indicator = %u\n", ts->pat.section_syntax_indicator);

    ts->pat.zero_byte = get_bits(reader, 1);
    ts->pat.reserved = get_bits(reader, 2);

    LOG("  reserved = %u\n", ts->pat.reserved);
    ts->pat.section_length = get_bits(reader, 12);

    LOG("  section_length = %u\n", ts->pat.section_length);
    ts->pat.transport_stream_id = get_bits(reader, 16);

    LOG("  transport_stream_id = %u\n", ts->pat.transport_stream_id);
    ts->pat.reserved2 = get_bits(reader, 2);

    LOG("  reserved2 = %u\n", ts->pat.reserved2);
    ts->pat.version_number = get_bits(reader, 5);

    LOG("  version_number = %u\n", ts->pat.version_number);
    ts->pat.current_next_indicator = get_bits(reader, 1);

    LOG("  current_next_indicator = %u\n", ts->pat.current_next_indicator);
    ts->pat.section_number = get_bits(reader, 8);

    LOG("  section_number = %u\n", ts->pat.section_number);
    ts->pat.last_section_number = get_bits(reader, 8);

    LOG("  last_section_number = %u\n", ts->pat.last_section_number);

    size_t numProgramBytes = (ts->pat.section_length - 5 /* header */ - 4 /* crc */);
    LOG("  numProgramBytes = %ld\n", numProgramBytes);

    for (i = 0; i < numProgramBytes / 4; ++i)
    {
        PATLoopInfo* info = new PATLoopInfo;
        info->program_number = get_bits(reader, 16);
        LOG("    program_number = %u\n", info->program_number);
        info->reserved = get_bits(reader, 3);
        LOG("    reserved = %u\n", info->reserved);

        info->pid = get_bits(reader, 13);
        if (info->program_number == 0)
        {
            LOG("    network_PID = 0x%04x\n", info->pid);
        }
        else
        {
            unsigned programMapPID = info->pid;
            LOG("    program_map_PID = 0x%04x\n", programMapPID);

            AddProgram(ts, programMapPID);
        }
    }

    ts->pat.crc = get_bits(reader, 32);
    LOG("  CRC = 0x%08x\n", ts->pat.crc);
}

void AddProgram(TS *ts, uint32_t programMapPID){
    TSProgram* program = new TSProgram;
    program->program_map_pid = programMapPID;
    ts->programs.push_back(program);
}

bool ParseProgramMap(TS* ts, TSProgram *program, BitReader* reader){
    ts->pmt.table_id = get_bits(reader, 8);

    printf("****** PROGRAM MAP *****\n");
    printf("	table_id = %u\n", ts->pmt.table_id);

    ts->pmt.section_syntax_indicator = get_bits(reader, 1);
    printf("	section_syntax_indicator = %u\n", ts->pmt.section_syntax_indicator);

    // Reserved
    ts->pmt.zero_byte = get_bits(reader,1);
    ts->pmt.reserved = get_bits(reader,2);


    ts->pmt.section_length = get_bits(reader, 12);
    printf("  section_length = %u\n", ts->pmt.section_length);

    ts->pmt.program_number = get_bits(reader, 16);
    printf("  program_number = %u\n", ts->pmt.program_number);

    ts->pmt.reserved2 = get_bits(reader, 2);
    printf("  reserved = %u\n", ts->pmt.reserved2);

    ts->pmt.version_number = get_bits(reader, 5);
    printf("  version_number = %u\n", ts->pmt.version_number);

    ts->pmt.current_next_indicator = get_bits(reader, 1);
    printf("  current_next_indicator = %u\n", ts->pmt.current_next_indicator);

    ts->pmt.section_number = get_bits(reader, 8);
    printf("  section_number = %u\n", ts->pmt.section_number);

    ts->pmt.last_section_number = get_bits(reader, 8);
    printf("  last_section_number = %u\n", ts->pmt.last_section_number);

    ts->pmt.reserved3 = get_bits(reader, 3);
    printf("  reserved = %u\n", ts->pmt.reserved3);

    ts->pmt.PCR_PID = get_bits(reader, 13);
    printf("  PCR_PID = 0x%04x\n", ts->pmt.PCR_PID);

    ts->pmt.reserved4 = get_bits(reader, 4);
    printf("  reserved = %u\n", ts->pmt.reserved4);

    ts->pmt.program_info_length = get_bits(reader, 12);
    printf("  program_info_length = %u\n", ts->pmt.program_info_length);


    skip_bits(reader, ts->pmt.program_info_length * 8);  // skip descriptors

    // infoBytesRemaining is the number of bytes that make up the
    // variable length section of ES_infos. It does not include the
    // final CRC.
    size_t infoBytesRemaining = ts->pmt.section_length - 9 - ts->pmt.program_info_length - 4;

    while (infoBytesRemaining > 0)
    {
        PMTLoopInfo* info = new PMTLoopInfo;

        info->stream_type = get_bits(reader, 8);
        printf("    stream_type = 0x%02x\n", info->stream_type);

        info->reserved = get_bits(reader, 3);
        printf("    reserved = %u\n", info->reserved);

        info->elementary_pid = get_bits(reader, 13);
        printf("    elementary_PID = 0x%04x\n", info->elementary_pid);

        info->reserved2 = get_bits(reader, 4);
        printf("    reserved = %u\n", info->reserved2);

        info->es_info_lenght = get_bits(reader, 12);
        printf("    ES_info_length = %u\n", info->es_info_lenght);

        size_t info_bytes_remaining = info->es_info_lenght;
        while (info_bytes_remaining >= 2)
        {
            uint32_t descLength;
            printf("      tag = 0x%02x\n", get_bits(reader, 8));

            descLength = get_bits(reader, 8);
            printf("      len = %u\n", descLength);

            skip_bits(reader, descLength * 8);

            info_bytes_remaining -= descLength + 2;
        }

        if(GetStreamByPID(program, info->elementary_pid) == NULL)
            AddStream(program, info->elementary_pid, info->stream_type);

        infoBytesRemaining -= 5 + info->es_info_lenght;
        ts->pmt.nloops.push_back(info);
    }

    ts->pmt.crc = get_bits(reader, 32);
    printf("  CRC = 0x%08x\n", ts->pmt.crc);
    printf("****** PROGRAM MAP *****\n");
}

bool ParsePayload(TS* ts,BitReader* reader,uint32_t pid, uint32_t payload_unit_start_indicator){
    int handle = 0;
    if(pid == 0){
        if(payload_unit_start_indicator){
            uint32_t skips = get_bits(reader,8);
            skip_bits(reader,skips * 8);
        }
        return ParsePAT(ts,reader);
    }

    bool ret = false;
    for(int i = 0; i < ts->programs.size(); ++i){
        TSProgram* program = ts->programs[i];
        if(program == NULL){
            continue;
        }

        if(program->program_map_pid == pid){
            if(payload_unit_start_indicator){
                uint32_t skips = get_bits(reader,8);
                skip_bits(reader,skips * 8);
            }
            ret = ParseProgramMap(ts,program,reader);
            handle = 1;
            break;
        }
        else{
            TSStream* stream = GetStreamByPID(program,pid);
            if(stream == NULL){
                continue;
            }
            ret = ParseStream(stream,payload_unit_start_indicator,reader);
        }
    }
    if(!handle){
        LOG("PID 0x%04x not handled.\n", pid);
    }
    return ret;
}

bool ParsePacket(TS* ts,BitReader* reader){
    TSPacket* packet = new TSPacket;
    packet->sync_byte = get_bits(reader,8);
    if(packet->sync_byte != TS_SYNC_CODE){
        delete packet;
        return false;
    }

    packet->transport_error_indicator = get_bits(reader,1);
    if(packet->transport_error_indicator !=0){
        delete packet;
        return false;
    }

    packet->payload_unit_start_indicator = get_bits(reader,1);
    LOG("Payload unit start indicator: %u\n", packet->payload_unit_start_indicator);

    packet->transport_priority = get_bits(reader,1);
    LOG("Transport Priority: %u\n", packet->transport_priority);

    packet->pid = get_bits(reader,13);
    LOG("PID: 0x%04x\n", packet->pid);

    packet->transport_scrambling_control = get_bits(reader,2);
    LOG("Transport Scrambling Control: %u\n", packet->transport_scrambling_control);

    packet->adaptation_field_control = get_bits(reader,2);
    LOG("Adaptation field control: %u\n", packet->adaptation_field_control);

    packet->continuity_counter = get_bits(reader,4);
    LOG("Continuity Counter: %u\n", packet->continuity_counter);

    bool ret = false;
    if(packet->adaptation_field_control == 2 || packet->adaptation_field_control == 3){
        ret = ParseAdaptionField(ts,reader);
    }

    if(packet->adaptation_field_control == 1 || packet->adaptation_field_control == 3){
        ret = ParsePayload(ts,reader,packet->pid,packet->payload_unit_start_indicator);
    }
    delete packet;
    return ret;
}
