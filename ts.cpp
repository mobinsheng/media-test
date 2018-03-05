#include "ts.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include "bitreader.h"


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
    ts->pat.transport_stream_id = get_bits(reader,16);//get_bits(reader, 16);

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

TSStream *GetStreamByPID(TSProgram *program, uint32_t pid){

    for(int i = 0; i < program->streams.size(); ++i){
        TSStream* stream = program->streams[i];
        if(stream == NULL){
            continue;
        }
        if(stream->elementary_pid != pid){
            continue;
        }

        return stream;
    }
    return NULL;
}

TSProgram *GetProgramByPID(TS *ts, uint32_t pid){
    for(int i = 0; i < ts->programs.size(); ++i){
        TSProgram *program = ts->programs[i];
        if(program != NULL && program->program_map_pid == pid){
            return program;
        }
    }
    return NULL;
}

void AddStream(TSProgram *program, uint32_t elementaryPID, uint32_t streamType){
    TSStream* stream = new TSStream;
    stream->program = program;
    stream->elementary_pid = elementaryPID;
    stream->stream_type = streamType;
    program->streams.push_back(stream);
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

bool ParseStream(TSStream *stream, uint32_t payload_unit_start_indicator, BitReader* reader){
    size_t payloadSizeBits;

    if(payload_unit_start_indicator)
    {
        if(stream->payload_started)
        {
            FlushStreamData(stream);
        }
        stream->payload_started = 1;
    }

    if(!stream->payload_started)
    {
        return false;
    }

    payloadSizeBits = bitreader_size(reader);

    memcpy(stream->buffer + stream->buffer_size, bitreader_data(reader), payloadSizeBits / 8);
    stream->buffer_size += (payloadSizeBits / 8);
}

bool ParsePES(TSStream *stream, BitReader* reader){
    uint32_t packet_startcode_prefix = get_bits(reader, 24);
    uint32_t stream_id = get_bits(reader, 8);
    uint32_t PES_packet_length = get_bits(reader, 16);

    if (stream_id != 0xbc  // program_stream_map
            && stream_id != 0xbe  // padding_stream
            && stream_id != 0xbf  // private_stream_2
            && stream_id != 0xf0  // ECM
            && stream_id != 0xf1  // EMM
            && stream_id != 0xff  // program_stream_directory
            && stream_id != 0xf2  // DSMCC
            && stream_id != 0xf8)   // H.222.1 type E
    {
        uint32_t PTS_DTS_flags;
        uint32_t ESCR_flag;
        uint32_t ES_rate_flag;
        uint32_t DSM_trick_mode_flag;
        uint32_t additional_copy_info_flag;
        uint32_t PES_header_data_length;
        uint32_t optional_bytes_remaining;
        uint64_t PTS = 0, DTS = 0;

        skip_bits(reader, 8);

        PTS_DTS_flags = get_bits(reader, 2);
        ESCR_flag = get_bits(reader, 1);
        ES_rate_flag = get_bits(reader, 1);
        DSM_trick_mode_flag = get_bits(reader, 1);
        additional_copy_info_flag = get_bits(reader, 1);

        skip_bits(reader, 2);

        PES_header_data_length = get_bits(reader, 8);
        optional_bytes_remaining = PES_header_data_length;

        if (PTS_DTS_flags == 2 || PTS_DTS_flags == 3)
        {
            skip_bits(reader, 4);
            PTS = ParseTSTimestamp(reader);
            skip_bits(reader, 1);

            optional_bytes_remaining -= 5;

            if (PTS_DTS_flags == 3)
            {
                skip_bits(reader, 4);

                DTS = ParseTSTimestamp(reader);
                skip_bits(reader, 1);

                optional_bytes_remaining -= 5;
            }
        }

        if (ESCR_flag)
        {
            skip_bits(reader, 2);

            uint64_t ESCR = ParseTSTimestamp(reader);

            skip_bits(reader, 11);

            optional_bytes_remaining -= 6;
        }

        if (ES_rate_flag)
        {
            skip_bits(reader, 24);
            optional_bytes_remaining -= 3;
        }

        skip_bits(reader, optional_bytes_remaining * 8);

        // ES data follows.
        if (PES_packet_length != 0)
        {
            uint32_t dataLength = PES_packet_length - 3 - PES_header_data_length;

            // Signaling we have payload data
            OnPayloadData(stream, PTS_DTS_flags, PTS, DTS, (uint8_t*)bitreader_data(reader), dataLength);

            skip_bits(reader, dataLength * 8);
        }
        else
        {
            size_t payloadSizeBits;
            // Signaling we have payload data
            OnPayloadData(stream, PTS_DTS_flags, PTS, DTS, (uint8_t*)bitreader_data(reader), bitreader_size(reader) / 8);

            payloadSizeBits = bitreader_size(reader);
        }
    }
    else if (stream_id == 0xbe)
    {  // padding_stream
        skip_bits(reader, PES_packet_length * 8);
    }
    else
    {
        skip_bits(reader, PES_packet_length * 8);
    }
}

int64_t ParseTSTimestamp(BitReader* reader){
    int64_t result = ((uint64_t)get_bits(reader, 3)) << 30;
    skip_bits(reader, 1);
    result |= ((uint64_t)get_bits(reader, 15)) << 15;
    skip_bits(reader, 1);
    result |= get_bits(reader, 15);

    return result;
}

void FlushStreamData(TSStream *stream){
    BitReader reader;
    bitreader_init(&reader, (uint8_t *)stream->buffer, stream->buffer_size);

    ParsePES(stream, &reader);

    stream->buffer_size = 0;
}

// convert PTS to timestamp
int64_t convertPTSToTimestamp(TSStream *stream, uint64_t PTS)
{
    if (!stream->program->first_pts_valid)
    {
        stream->program->first_pts_valid = 1;
        stream->program->first_pts = PTS;
        PTS = 0;
    }
    else if (PTS < stream->program->first_pts)
    {
        PTS = 0;
    }
    else
    {
        PTS -= stream->program->first_pts;
    }

    return (PTS * 100) / 9;
}

void OnPayloadData(TSStream *stream, uint32_t PTS_DTS_flag, uint64_t PTS, uint64_t DTS, uint8_t *data, size_t size){
    int64_t timeUs = convertPTSToTimestamp(stream, PTS);
    if(stream->stream_type == TS_STREAM_VIDEO)
    {
        printf("Payload Data!!!! Video (%02x), PTS: %lld, DTS:%lld, Size: %ld\n", stream->stream_type, PTS, DTS, size);
    }
    else if(stream->stream_type == TS_STREAM_AUDIO)
    {
        printf("Payload Data!!!! Audio (%02x), PTS: %lld, DTS:%lld, Size: %ld\n", stream->stream_type, PTS, DTS, size);
    }
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
