#ifndef TS_H
#define TS_H

#include <stdio.h>
#include <stdint.h>
#include <memory.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <deque>
#include <vector>
#include <string>
using namespace std;
#include "bitreader.h"

/*
 * PAT中包含了program（节目）的编号（program number）以及对应的PMT的PID，
 * program和PMT是一一对应的，因此program number 和 PMT的PID也是一一对应的
 * PMT就相当于program和节目元素之间的桥梁，
 * 通过program number可以找到PMT的PID，也就找到了PMT的信息
 * 可以这样认为：program number是对外的（针对用户），而PMT的PID是对内的
 * ts的包中传输的都是pid（可能是program的pid，也可能是stream的pid）
 *
 * 例如有一个包，我们解析出它的pid
 * 1、如果这个pid等于某个PMT的pid，那么表示这个包携带了PMT的信息，
 * 我们应该解析这个PMT，并更新它
 * 2、如果这个pid不等于program的pid，那么我们应该看它是不是program中某一个流的pid，如果是
 * 我们就应该解析它
 *
 * program可以包含多个流，例如音频流、视频流、字幕流等等
 * ES（Elementary stream）就是基本的音视频流
 * PES是ES加上头部之后的数据
 * PS（program stream）就是多个PES复合而成的
 */
enum TSEnum{
    TS_PACKET_LENGTH  =188,
    TS_STREAM_VIDEO	 = 0x1b,
    TS_STREAM_AUDIO = 0x0f,
    TS_SYNC_CODE = 0x47,
};

struct TS;
struct TSStream;
struct TSProgram;
struct TSPacket;

struct AdaptationField{
    uint32_t adaptation_field_length;
    uint32_t discontinuity_indicator;
    uint32_t random_access_indicator;
    uint32_t elementary_stream_priority_indicator;
    uint32_t PCR_flag;
    uint32_t OPCR_flag;
    uint32_t splicing_point_flag;
    uint32_t transport_private_data_flag;
    uint32_t adaptation_field_extension_flag;
    uint64_t PCR;
    uint64_t OPCR;
    uint32_t splice_countdown;
};

struct TSPacket{
    uint32_t sync_byte;
    uint32_t transport_error_indicator;
    /*
     * payload_unit_start_indicator表明了一个新的pes/psi（即pat、pmt等）
     */ 
    uint32_t payload_unit_start_indicator;
    uint32_t transport_priority;
    uint32_t pid;
    uint32_t transport_scrambling_control;
    uint32_t adaptation_field_control;
    uint32_t continuity_counter;

    bool has_adaptation_field;
    AdaptationField adaptation_field;
};



struct PAT{ // Program Association Table

    // 这是PAT中携带的与节目、PMT相关的信息
    struct PATLoopInfo{
        uint32_t program_number;
        uint32_t reserved;
        uint32_t pid;// network_pid or program_map_pid
    };

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


struct PMT{ // program map table

    // 这是PMT中携带的，与PES、流相关的信息
    struct PMTLoopInfo{
        uint32_t stream_type;
        uint32_t reserved;
        uint32_t elementary_pid;
        uint32_t reserved2;
        uint32_t es_info_lenght;
    };

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

struct PESOptional{

    uint32_t PES_scrambling_control;
    uint32_t PES_priority;
    uint32_t data_alignment_indicator;
    uint32_t copyright;
    uint32_t original_or_copy;

    uint32_t PTS_DTS_flags;
    uint32_t ESCR_flag;
    uint32_t ES_rate_flag;
    uint32_t DSM_trick_mode_flag;
    uint32_t additional_copy_info_flag;
    uint32_t PES_header_data_length;
    uint32_t optional_bytes_remaining;
    uint64_t PTS = 0;
    uint64_t DTS = 0;
};

struct PES{
    uint32_t packet_startcode_prefix ;
    uint32_t stream_id;
    uint32_t PES_packet_length;
    PESOptional optional;
};


struct TSProgram;
struct TSStream{
    TSProgram* program;
    PES pes;
    uint32_t stream_type;
    uint32_t elementary_pid;
    uint32_t payload_started;
    uint8_t* buffer;
    size_t buffer_size;
    size_t capacity;

    TSStream(){
        program = NULL;
        stream_type = 0;
        elementary_pid = 0;
        payload_started = 0;

        capacity = 1024 * 1024;
        buffer = (uint8_t*)malloc(capacity);
        buffer_size = 0;
    }

    ~TSStream(){
        free(buffer);
    }

    void push_data(const uint8_t* data,size_t size){
        if(buffer_size >= capacity){
            capacity += 1024*128;
            uint8_t* tmp = (uint8_t*)realloc(buffer,capacity);
            if(tmp == NULL){
                assert(0);
            }
            buffer = tmp;
        }
        memcpy(buffer + buffer_size, data, size);
        buffer_size += size;
    }
};

struct TSProgram{
    uint32_t program_number;
    uint32_t program_map_pid;
    PMT pmt;
    uint64_t first_pts;
    int first_pts_valid;
    deque<TSStream*> streams;

    TSProgram(){
        program_map_pid = 0;
        first_pts = 0;
        first_pts_valid = 0;
    }

    ~TSProgram(){
        for(size_t i = 0; i < pmt.nloops.size(); ++i){
            PMT::PMTLoopInfo* info = pmt.nloops[i];
            delete info;
        }

        for(size_t i = 0; i < streams.size(); ++i){
            TSStream* s = streams[i];
            delete s;
        }
    }

    TSStream* find_stream(uint32_t pid){
        for(int i = 0; i < streams.size(); ++i){
            TSStream* stream = streams[i];
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

    void add_stream(uint32_t elementaryPID, uint32_t streamType){
        TSStream* stream = new TSStream;
        stream->program = this;
        stream->elementary_pid = elementaryPID;
        stream->stream_type = streamType;
        streams.push_back(stream);
    }
};

typedef void (*UnpackDataCallback)(TSStream*, uint32_t PTS_DTS_flag,
                           uint64_t PTS, uint64_t DTS,
                           uint8_t *data, size_t size);



struct TSParser{
    PAT pat;
    deque<TSProgram*> programs;

    UnpackDataCallback unpack_data_callback;
    // callback after parse TS packet

    TSParser(UnpackDataCallback call=NULL){
        unpack_data_callback = call;
    }

    ~TSParser(){
        Clean();
    }

    void Clean(){
        size_t i = 0;

        for(i = 0; i < pat.nloops.size(); ++i){
            PAT::PATLoopInfo* info = pat.nloops[i];
            delete info;
        }



        for(i = 0; i < programs.size(); ++i){
            TSProgram* program = programs[i];
            delete program;
        }
    }

    TSProgram *find_program(uint32_t pid){
        for(int i = 0; i < programs.size(); ++i){
            TSProgram *program = programs[i];
            if(program != NULL && program->program_map_pid == pid){
                return program;
            }
        }
        return NULL;
    }

    // 新增一个program
    void add_program(uint32_t program_number,uint32_t programMapPID){
        TSProgram* program = new TSProgram;
        program->program_number = program_number;
        program->program_map_pid = programMapPID;
        programs.push_back(program);
    }

    bool parse_adaption_field(BitReader* reader,TSPacket* packet);

    bool parse_payload(BitReader* reader,uint32_t pid, uint32_t payload_unit_start_indicator);

    bool parse_pat(BitReader* reader);//ProgramAssociationTable

    bool parse_pmt(TSProgram *program, BitReader* reader);

    bool parse_stream(TSStream *stream, uint32_t payload_unit_start_indicator, BitReader* reader);

    bool parse_pes(TSStream *stream, BitReader* reader);

    int64_t parse_timestamp(BitReader* reader);

    void flush_stream_data(TSStream *stream);
};

bool ParsePacket(TSParser* ts, BitReader* reader,TSPacket* packet);

#endif // TS_H
