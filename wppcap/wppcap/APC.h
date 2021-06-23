#pragma once
#include <windivert.h>

//过滤器类型
#define filter_type_sniff WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY
#define filter_type_drop WINDIVERT_FLAG_DROP
#define filter_type_modify  WINDIVERT_FLAG_RECV_ONLY 

//过滤器参数
#define SNIFF_QUEUE_LEN 8192
#define SNIFF_QUEUE_TIME 5000
#define SNIFF_QUEUE_SIZE 4194304

#define MODIFY_QUEUE_LEN  20480
#define MODIFY_QUEUE_TIME 8000
#define MODIFY_QUEUE_SIZE 33554432


//线程个数
#define thread_num 1

//buffer大小
#define maxbuf 2048 
//每个数据包最多就才1500字节