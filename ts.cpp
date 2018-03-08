#include "ts.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include "bitreader.h"


#define ELEMENTS 10


#define LOG printf
//#define LOG(format,...) //printf(format,__VA_ARGS__)

static void OnPayloadData(TSStream *stream, uint32_t PTS_DTS_flag, uint64_t PTS, uint64_t DTS, uint8_t *data, size_t size);

void DumpPAT(PAT& pat){

    LOG("  table_id = %u\n", pat.table_id);
    LOG("  section_syntax_indicator = %u\n", pat.section_syntax_indicator);
    LOG("  reserved = %u\n", pat.reserved);
    LOG("  section_length = %u\n", pat.section_length);
    LOG("  transport_stream_id = %u\n", pat.transport_stream_id);
    LOG("  reserved2 = %u\n", pat.reserved2);
    LOG("  version_number = %u\n", pat.version_number);
    LOG("  current_next_indicator = %u\n", pat.current_next_indicator);
    LOG("  section_number = %u\n", pat.section_number);
    LOG("  last_section_number = %u\n", pat.last_section_number);
    for (size_t i = 0; i < pat.nloops.size(); ++i)
    {
        PAT::PATLoopInfo* info = pat.nloops[i];
        LOG("    program_number = %u\n", info->program_number);
        LOG("    reserved = %u\n", info->reserved);
        LOG("    PID = 0x%04x\n", info->pid);
    }
    LOG("  CRC = 0x%08x\n", pat.crc);
}

void DumpPMT(PMT& pmt){

    LOG("****** PROGRAM MAP *****\n");
    LOG("	table_id = %u\n", pmt.table_id);
    LOG("	section_syntax_indicator = %u\n", pmt.section_syntax_indicator);
    LOG("  section_length = %u\n", pmt.section_length);
    LOG("  program_number = %u\n", pmt.program_number);
    LOG("  reserved = %u\n", pmt.reserved2);
    LOG("  version_number = %u\n", pmt.version_number);
    LOG("  current_next_indicator = %u\n", pmt.current_next_indicator);
    LOG("  section_number = %u\n", pmt.section_number);
    LOG("  last_section_number = %u\n", pmt.last_section_number);
    LOG("  reserved = %u\n", pmt.reserved3);
    LOG("  PCR_PID = 0x%04x\n", pmt.PCR_PID);
    LOG("  reserved = %u\n", pmt.reserved4);
    LOG("  program_info_length = %u\n", pmt.program_info_length);
    size_t i = 0;
    for (i = 0; i < pmt.nloops.size();++i)
    {
        PMT::PMTLoopInfo* info = pmt.nloops[i];
        LOG("    stream_type = 0x%02x\n", info->stream_type);
        LOG("    reserved = %u\n", info->reserved);
        LOG("    elementary_PID = 0x%04x\n", info->elementary_pid);
        LOG("    reserved = %u\n", info->reserved2);
        LOG("    ES_info_length = %u\n", info->es_info_lenght);
    }
    LOG("  CRC = 0x%08x\n", pmt.crc);
    LOG("****** PROGRAM MAP *****\n");
}

bool DumpPacket(TSPacket* packet){
    LOG("-----Packet Head begin-----\n");
    LOG("Payload unit start indicator: %u\n", packet->payload_unit_start_indicator);
    LOG("Transport Priority: %u\n", packet->transport_priority);
    LOG("PID: 0x%04x\n", packet->pid);
    LOG("Transport Scrambling Control: %u\n", packet->transport_scrambling_control);
    LOG("Adaptation field control: %u\n", packet->adaptation_field_control);
    LOG("Continuity Counter: %u\n", packet->continuity_counter);
    LOG("Continuity Counter: %u\n", packet->continuity_counter);
    LOG("-----Packet Head end-----\n");
}

bool TSParser::parse_adaption_field(BitReader* reader,TSPacket* packet){
    AdaptationField* af = &packet->adaptation_field;
    af->adaptation_field_length = get_bits(reader, 8);
    int bits = af->adaptation_field_length * 8;
    /*if(af->adaptation_field_length < 0){
        return true;
    }
    af->discontinuity_indicator = get_bits(reader,1);
    af->random_access_indicator = get_bits(reader,1);
    af->elementary_stream_priority_indicator = get_bits(reader,1);
    af->PCR_flag = get_bits(reader,1);
    af->OPCR_flag = get_bits(reader,1);
    af->splicing_point_flag = get_bits(reader,1);
    af->transport_private_data_flag = get_bits(reader,1);
    af->adaptation_field_extension_flag = get_bits(reader,1);

    bits -= (1+1+1+1+1+1+1+1);

    if(bits >= 48){
        int64_t base = get_bits(reader,33);
        bits -= 33;
        skip_bits(reader,6);
        int64_t extension = get_bits(reader,9);
        af->PCR = base * 300 + extension;
    }

    if(bits >= 48){
        af->OPCR = get_bits(reader,48);
        bits -= 48;
    }

    if(bits >= 8){
        af->splice_countdown = get_bits(reader,8);
        bits -= 8;
    }*/

    skip_bits(reader,bits);
}

bool TSParser::parse_pat(BitReader* reader){
    size_t i;

    pat.table_id = get_bits(reader, 8);
    pat.section_syntax_indicator = get_bits(reader, 1);
    pat.zero_byte = get_bits(reader, 1);
    pat.reserved = get_bits(reader, 2);
    pat.section_length = get_bits(reader, 12);
    pat.transport_stream_id = get_bits(reader,16);//get_bits(reader, 16);
    pat.reserved2 = get_bits(reader, 2);
    pat.version_number = get_bits(reader, 5);
    pat.current_next_indicator = get_bits(reader, 1);
    pat.section_number = get_bits(reader, 8);
    pat.last_section_number = get_bits(reader, 8);

    size_t numProgramBytes = (pat.section_length - 5 /* header */ - 4 /* crc */);

    for (i = 0; i < numProgramBytes / 4; ++i)
    {
        PAT::PATLoopInfo* info = new PAT::PATLoopInfo;
        info->program_number = get_bits(reader, 16);
        info->reserved = get_bits(reader, 3);
        info->pid = get_bits(reader, 13);
        if (info->program_number == 0)
        {
			// 网络pid相关，这里不处理
        }
        else
        {
			// pat里面包含了PMT（program map table）的信息
            // 也就是说PMT和grogram是一一对应的
            unsigned programMapPID = info->pid;
            // 新增一个program
            add_program(info->program_number,programMapPID);
        }
    }

    pat.crc = get_bits(reader, 32);
    //LOG("-----PAT Head begin-----\n");
    //DumpPAT(pat);
    //LOG("-----PAT Head end-----\n");
}

/*
 * PMT中包含了流（对应PES）的信息（主要是PID，其他详细的PES信息在后面的包中传输），一个节目可以包含多个流
 */
bool TSParser::parse_pmt(TSProgram *program, BitReader* reader){
    PMT& pmt = program->pmt;
    pmt.table_id = get_bits(reader, 8);
    pmt.section_syntax_indicator = get_bits(reader, 1);
    pmt.zero_byte = get_bits(reader,1);
    pmt.reserved = get_bits(reader,2);
    pmt.section_length = get_bits(reader, 12);
    pmt.program_number = get_bits(reader, 16);
    pmt.reserved2 = get_bits(reader, 2);
    pmt.version_number = get_bits(reader, 5);
    pmt.current_next_indicator = get_bits(reader, 1);
    pmt.section_number = get_bits(reader, 8);
    pmt.last_section_number = get_bits(reader, 8);
    pmt.reserved3 = get_bits(reader, 3);
    pmt.PCR_PID = get_bits(reader, 13);
    pmt.reserved4 = get_bits(reader, 4);
    pmt.program_info_length = get_bits(reader, 12);

    skip_bits(reader, pmt.program_info_length * 8);  // skip descriptors

    // infoBytesRemaining is the number of bytes that make up the
    // variable length section of ES_infos. It does not include the
    // final CRC.
    size_t infoBytesRemaining = pmt.section_length - 9 - pmt.program_info_length - 4;

    while (infoBytesRemaining > 0)
    {
        PMT::PMTLoopInfo* info = new PMT::PMTLoopInfo;
        pmt.nloops.push_back(info);
        info->stream_type = get_bits(reader, 8);
        info->reserved = get_bits(reader, 3);
        info->elementary_pid = get_bits(reader, 13);
        info->reserved2 = get_bits(reader, 4);
        info->es_info_lenght = get_bits(reader, 12);
        int info_bytes_remaining = info->es_info_lenght;
        while (info_bytes_remaining >= 2)
        {
            uint32_t descLength;
            descLength = get_bits(reader, 8);
            skip_bits(reader, descLength * 8);
            info_bytes_remaining -= descLength + 2;
        }

        if(program->find_stream(info->elementary_pid) == NULL)
            program->add_stream(info->elementary_pid, info->stream_type);

        infoBytesRemaining -= 5 + info->es_info_lenght;
    }

    pmt.crc = get_bits(reader, 32);
    //LOG("-----PMT Head begin-----\n");
    //DumpPMT(pmt);
    //LOG("-----PMT Head end-----\n");
}

bool TSParser::parse_payload(BitReader* reader,uint32_t pid, uint32_t payload_unit_start_indicator){
    int handle = 0;
    // pid等于0表示出现pat
    if(pid == 0){
		/*
         * payload_unit_start_indicator，
         * 但是当前是PSI（pat、pmt等）信息，因此要跳过一些字节（用于调整）
		 */ 
        if(payload_unit_start_indicator){
            uint32_t skips = get_bits(reader,8);
            skip_bits(reader,skips * 8);
        }

        return parse_pat(reader);
    }

    // pid不等于0,意味着明确地指定了一个program或者stream的PID
    bool ret = false;
    for(int i = 0; i < programs.size(); ++i){
        TSProgram* program = programs[i];
        if(program == NULL){
            continue;
        }

        /*
         * 如果指明了PMT的PID（注意不是program number）
         * 那么表示这个包传输的是PMT的信息
         * PMT包含了PES的PID
         * 解析PMT的时候可以把流加上
         */
        if(program->program_map_pid == pid){
            if(payload_unit_start_indicator){
                uint32_t skips = get_bits(reader,8);
                skip_bits(reader,skips * 8);
            }
            ret = parse_pmt(program,reader);
            handle = 1;
            break;
        }
        /*
         * 如果不是PMT的id，那么判断是不是stream的pid
         * stream在解析PMT的时候就已经增加了
         * 如果是流的pid，那么解析PES或者流数据
         */
        else{
            TSStream* stream = program->find_stream(pid);
            if(stream == NULL){
                continue;
            }
            ret = parse_stream(stream,payload_unit_start_indicator,reader);
        }
    }
    if(!handle){
        LOG("PID 0x%04x not handled.\n", pid);
    }
    return ret;
}

bool TSParser::parse_stream(TSStream *stream, uint32_t payload_unit_start_indicator, BitReader* reader){
    size_t payloadSizeBits;
    // 出现新的PES
    // 这段的逻辑是，把payload先全部存起来，直到遇见下一段payload
    // 然后才开始解析当前的payload
    if(payload_unit_start_indicator)
    {
        if(stream->payload_started)
        {
            flush_stream_data(stream);
        }
        stream->payload_started = 1;
    }

    if(!stream->payload_started)
    {
        return false;
    }

    if(payload_unit_start_indicator){
        //flush_stream_data(stream);
    }

    payloadSizeBits = bitreader_size(reader);

    stream->push_data(bitreader_data(reader), payloadSizeBits / 8);
}

bool TSParser::parse_pes(TSStream *stream, BitReader* reader){
    PES& pes = stream->pes;

    pes.packet_startcode_prefix = get_bits(reader, 24);
    pes.stream_id = get_bits(reader, 8);
    pes.PES_packet_length = get_bits(reader, 16);

    uint32_t stream_id = pes.stream_id;

    if (stream_id != 0xbc  // program_stream_map
            && stream_id != 0xbe  // padding_stream
            && stream_id != 0xbf  // private_stream_2
            && stream_id != 0xf0  // ECM
            && stream_id != 0xf1  // EMM
            && stream_id != 0xff  // program_stream_directory
            && stream_id != 0xf2  // DSMCC
            && stream_id != 0xf8)   // H.222.1 type E
    {
        skip_bits(reader, 2); // 10
        pes.optional.PES_scrambling_control = get_bits(reader,2);
        pes.optional.PES_priority = get_bits(reader,1);
        pes.optional.data_alignment_indicator = get_bits(reader,1);
        pes.optional.copyright = get_bits(reader,1);
        pes.optional.original_or_copy = get_bits(reader,1);

        //skip_bits(reader, 8);

        pes.optional.PTS_DTS_flags = get_bits(reader, 2);
        pes.optional.ESCR_flag = get_bits(reader, 1);
        pes.optional.ES_rate_flag = get_bits(reader, 1);
        pes.optional.DSM_trick_mode_flag = get_bits(reader, 1);
        pes.optional.additional_copy_info_flag = get_bits(reader, 1);

        skip_bits(reader, 2);

        pes.optional.PES_header_data_length = get_bits(reader, 8);
        pes.optional.optional_bytes_remaining = pes.optional.PES_header_data_length;

        if (pes.optional.PTS_DTS_flags == 2 || pes.optional.PTS_DTS_flags == 3)
        {
            skip_bits(reader, 4);
            pes.optional.PTS = parse_timestamp(reader);
            skip_bits(reader, 1);

            pes.optional.optional_bytes_remaining -= 5;

            if (pes.optional.PTS_DTS_flags == 3)
            {
                skip_bits(reader, 4);

                pes.optional.DTS = parse_timestamp(reader);
                skip_bits(reader, 1);

                pes.optional.optional_bytes_remaining -= 5;
            }
        }

        if (pes.optional.ESCR_flag)
        {
            skip_bits(reader, 2);

            uint64_t ESCR = parse_timestamp(reader);

            skip_bits(reader, 11);

            pes.optional.optional_bytes_remaining -= 6;
        }

        if (pes.optional.ES_rate_flag)
        {
            skip_bits(reader, 24);
            pes.optional.optional_bytes_remaining -= 3;
        }

        skip_bits(reader, pes.optional.optional_bytes_remaining * 8);

        // ES data follows.
        if (pes.PES_packet_length != 0)
        {
            uint32_t dataLength = pes.PES_packet_length - 3 - pes.optional.PES_header_data_length;

            // Signaling we have payload data
            void (*pfun)(TSStream*, uint32_t PTS_DTS_flag,
                                       uint64_t PTS, uint64_t DTS,
                                       uint8_t *data, size_t size);

            if(unpack_data_callback){
                unpack_data_callback(stream,
                              pes.optional.PTS_DTS_flags,
                              pes.optional.PTS,
                              pes.optional.DTS,
                              (uint8_t*)bitreader_data(reader),
                              dataLength);
            }
            else{
                OnPayloadData(stream,
                              pes.optional.PTS_DTS_flags,
                              pes.optional.PTS,
                              pes.optional.DTS,
                              (uint8_t*)bitreader_data(reader),
                              dataLength);
            }


            skip_bits(reader, dataLength * 8);
        }
        else
        {
            size_t payloadSizeBits;
            // Signaling we have payload data
            if(unpack_data_callback){
                unpack_data_callback(stream,
                              pes.optional.PTS_DTS_flags,
                              pes.optional.PTS,
                              pes.optional.DTS,
                              (uint8_t*)bitreader_data(reader),
                              bitreader_size(reader) / 8);
            }
            else{
                OnPayloadData(stream,
                              pes.optional.PTS_DTS_flags,
                              pes.optional.PTS,
                              pes.optional.DTS,
                              (uint8_t*)bitreader_data(reader),
                              bitreader_size(reader) / 8);
            }

            payloadSizeBits = bitreader_size(reader);
        }
    }
    else if (stream_id == 0xbe)
    {  // padding_stream
        skip_bits(reader, pes.PES_packet_length * 8);
    }
    else
    {
        skip_bits(reader, pes.PES_packet_length * 8);
    }
}

int64_t TSParser::parse_timestamp(BitReader* reader){
    int64_t result = ((uint64_t)get_bits(reader, 3)) << 30;
    skip_bits(reader, 1);
    result |= ((uint64_t)get_bits(reader, 15)) << 15;
    skip_bits(reader, 1);
    result |= get_bits(reader, 15);

    return result;
}

void TSParser::flush_stream_data(TSStream *stream){
    BitReader reader;
    bitreader_init(&reader, (uint8_t *)stream->buffer, stream->buffer_size);

    parse_pes(stream, &reader);

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

static void OnPayloadData(TSStream *stream, uint32_t PTS_DTS_flag, uint64_t PTS, uint64_t DTS, uint8_t *data, size_t size){
    int64_t timeUs = convertPTSToTimestamp(stream, PTS);
    if(stream->stream_type == TS_STREAM_VIDEO)
    {
        LOG("Payload Data!!!! Video (%02x), PTS: %lld, DTS:%lld, Size: %ld\n", stream->stream_type, PTS, DTS, size);
    }
    else if(stream->stream_type == TS_STREAM_AUDIO)
    {
        LOG("Payload Data!!!! Audio (%02x), PTS: %lld, DTS:%lld, Size: %ld\n", stream->stream_type, PTS, DTS, size);
    }
}

/*
 * parse a ts packet
 */
bool ParsePacket(TSParser* ts,BitReader* reader,TSPacket* packet){

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

    packet->transport_priority = get_bits(reader,1);

    packet->pid = get_bits(reader,13);

    packet->transport_scrambling_control = get_bits(reader,2);

    packet->adaptation_field_control = get_bits(reader,2);

    packet->continuity_counter = get_bits(reader,4);

    DumpPacket(packet);

    bool ret = false;
    if(packet->adaptation_field_control == 2 || packet->adaptation_field_control == 3){
        ret = ts->parse_adaption_field(reader,packet);
    }

    if(packet->adaptation_field_control == 1 || packet->adaptation_field_control == 3){
        ret = ts->parse_payload(reader,packet->pid,packet->payload_unit_start_indicator);
    }

    return ret;
}

